package redis

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// minimum redis connection pool size
const MAX_ACTIVE = 5

type Client interface {
	Close()
	Ping() error
	Del(key string) error
	NewScript(script string) Script
}

type ClientImpl struct {
	mu                sync.Mutex
	conns             chan net.Conn
	addr              string
	maxActive         int
	dialTimeout       time.Duration
	username          string
	auth              string
	db                int
	connectionTimeout time.Duration
	tlsCfg            *tls.Config
}

// Options configures the client. It replaces the previous positional
// NewClient(addr, db, password, timeout) signature, which had run out of room.
type Options struct {
	// Addr is host:port for the Redis/Valkey endpoint.
	Addr string
	// DB is the database index selected after AUTH.
	DB uint
	// Username, when set, selects the two-argument `AUTH <username> <password>`
	// form introduced with Redis 6 ACLs. Empty keeps the single-argument
	// `AUTH <password>` form, so existing deployments are unaffected.
	Username string
	// Password is the AUTH secret.
	Password string
	// ConnectionTimeout bounds each read and write, and — doubled — the dial.
	ConnectionTimeout time.Duration

	// TLS turns the handshake on with no trust material of our own, which is
	// what a managed endpoint presenting a publicly-rooted certificate needs.
	// It is ALSO implied by any of the four settings below, so an operator who
	// supplies a CA does not additionally have to remember this flag.
	TLS bool
	// CACertFile is a PEM bundle the server certificate is verified against.
	CACertFile string
	// ClientCertFile and ClientKeyFile are an optional client keypair for
	// mutual TLS. They must be set together.
	ClientCertFile string
	ClientKeyFile  string
	// ServerName is the name verified against the server certificate. When
	// empty it is derived from Addr.
	ServerName string
}

func tlsRequested(o Options) bool {
	return o.TLS ||
		o.CACertFile != "" ||
		o.ClientCertFile != "" ||
		o.ClientKeyFile != "" ||
		o.ServerName != ""
}

func hostFromAddr(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func buildTLSConfig(o Options) (*tls.Config, error) {
	// A half-supplied keypair is a mistake, not a downgrade signal.
	if (o.ClientCertFile == "") != (o.ClientKeyFile == "") {
		return nil, errors.New("redis: clientCertFile and clientKeyFile must be set together")
	}

	name := o.ServerName
	if name == "" {
		name = hostFromAddr(o.Addr)
	}
	if name == "" {
		return nil, errors.New("redis: cannot derive a TLS server name from address " +
			strconv.Quote(o.Addr) + "; set redisServerName")
	}

	// ServerName is mandatory: tls.Client does not infer it, and without it
	// verification fails. InsecureSkipVerify is deliberately absent — there is
	// no flag and no escape hatch.
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name}

	if o.CACertFile != "" {
		caPEM, err := os.ReadFile(o.CACertFile)
		if err != nil {
			return nil, errors.New("redis: reading caCertFile " + o.CACertFile + ": " + err.Error())
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("redis: no certificates parsed from caCertFile " + o.CACertFile)
		}
		cfg.RootCAs = pool
	}

	if o.ClientCertFile != "" {
		cert, err := tls.LoadX509KeyPair(o.ClientCertFile, o.ClientKeyFile)
		if err != nil {
			return nil, errors.New("redis: loading client keypair: " + err.Error())
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

// NewClient initializes a new redis client with connection pool
func NewClient(o Options) (Client, error) {
	maxActive := MAX_ACTIVE

	if maxActive <= 0 {
		return nil, errors.New("maxActive must be greater than 0")
	}

	var tlsCfg *tls.Config
	if tlsRequested(o) {
		var err error
		tlsCfg, err = buildTLSConfig(o)
		if err != nil {
			return nil, err
		}
	}

	r := &ClientImpl{
		conns:             make(chan net.Conn, maxActive),
		addr:              o.Addr,
		maxActive:         maxActive,
		dialTimeout:       o.ConnectionTimeout * 2,
		username:          o.Username,
		auth:              o.Password,
		db:                int(o.DB),
		connectionTimeout: o.ConnectionTimeout,
		tlsCfg:            tlsCfg,
	}

	// Prepopulate the pool with connections
	for i := 0; i < maxActive; i++ {
		conn, err := r.newConn()
		if err == nil {
			r.conns <- conn
		}
	}

	return r, nil
}

func (r *ClientImpl) newConn() (net.Conn, error) {
	tcp, err := net.DialTimeout("tcp", r.addr, r.dialTimeout)
	if err != nil {
		return nil, err
	}

	// net.DialTimeout bounds the TCP connect only. A TLS handshake against a
	// peer that accepts and then black-holes would hang forever without a
	// deadline of its own.
	var conn net.Conn = tcp
	if r.tlsCfg != nil {
		if err := tcp.SetDeadline(time.Now().Add(r.dialTimeout)); err != nil {
			_ = tcp.Close()
			return nil, err
		}
		tc := tls.Client(tcp, r.tlsCfg)
		if err := tc.Handshake(); err != nil {
			_ = tcp.Close()
			return nil, fmt.Errorf("TLS handshake to %s failed: %w", r.addr, err)
		}
		// Clear the handshake deadline; sendCommand sets its own per call.
		if err := tcp.SetDeadline(time.Time{}); err != nil {
			_ = tcp.Close()
			return nil, err
		}
		// Everything downstream reads and writes through the TLS conn — reading
		// the raw socket would hand us ciphertext.
		conn = tc
	}

	if r.auth != "" {
		// Two-argument AUTH when a username is configured (Redis 6+ ACLs),
		// single-argument otherwise.
		var resp *RedisResult
		var err error
		if r.username != "" {
			resp, err = sendCommand(conn, r.connectionTimeout, "AUTH", r.username, r.auth)
		} else {
			resp, err = sendCommand(conn, r.connectionTimeout, "AUTH", r.auth)
		}
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if resp.Success != RESP_SUCCESS || resp.Result != "OK" {
			_ = conn.Close()
			return nil, fmt.Errorf("not able to authenticate (%s)", resp.Result)
		}
	}
	resp, err := sendCommand(conn, r.connectionTimeout, "SELECT", fmt.Sprintf("%d", r.db))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.Success != RESP_SUCCESS || resp.Result != "OK" {
		_ = conn.Close()
		return nil, fmt.Errorf("not able to select db %d (%s)", r.db, resp.Result)
	}
	return conn, nil
}

// Get retrieves a connection from the pool
func (r *ClientImpl) get() (net.Conn, error) {
	select {
	case conn := <-r.conns:
		return conn, nil
	default:
		conn, err := r.newConn()
		return conn, err
	}
}

// Put returns a connection back to the pool
func (r *ClientImpl) put(conn net.Conn) error {
	if conn == nil {
		return errors.New("nil connection cannot be added to the pool")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// If the pool is full, just close the connection
	if len(r.conns) >= r.maxActive {
		conn.Close()
		return nil
	}

	r.conns <- conn
	return nil
}

// Close closes all the connections in the pool
func (r *ClientImpl) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	close(r.conns)
	for conn := range r.conns {
		conn.Close()
	}
}

const (
	RESP_SUCCESS = iota
	RESP_FAIL
	RESP_SUCCESS_WITH_RESULT
	RESP_SUCCESS_WITH_RESULTS
	RESP_UNKNOWN
)

type RedisResult struct {
	Success int
	Result  interface{}
	Results []interface{}
}

// sendCommand sends a command to Redis and returns the response.
func sendCommand(conn net.Conn, connectionTimeout time.Duration, args ...string) (*RedisResult, error) {
	// Construct the RESP command
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("*%d\r\n", len(args))) // Array prefix
	for _, arg := range args {
		sb.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(arg), arg)) // Bulk string for each argument
	}
	command := sb.String()

	// set read and write deadline
	err := conn.SetDeadline(time.Now().Add(connectionTimeout))
	if err != nil {
		return nil, fmt.Errorf("error setting deadline: %w", err)
	}

	// Send the command
	_, err = conn.Write([]byte(command))
	if err != nil {
		return nil, fmt.Errorf("error sending command: %w", err)
	}

	// Read the response
	reader := bufio.NewReader(conn)

	elt, err := readElement(reader)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}
	if elt.ElementType == ELEMENT_SIMPLE {
		return &RedisResult{
			Success: RESP_SUCCESS,
			Result:  elt.Value,
		}, nil
	}
	if elt.ElementType == ELEMENT_ERROR {
		return &RedisResult{
			Success: RESP_FAIL,
			Result:  elt.Value,
		}, nil
	}

	// simple element
	if elt.ElementType == ELEMENT_STRING || elt.ElementType == ELEMENT_INT {
		return &RedisResult{
			Success: RESP_SUCCESS_WITH_RESULT,
			Result:  elt.Value,
		}, nil
	}

	// array
	if elt.ElementType == ELEMENT_ARRAY {
		nb := elt.Value.(int)
		results := make([]interface{}, 0)

		for i := 0; i < nb; i++ {
			child, err := readElement(reader)
			if err != nil {
				return nil, fmt.Errorf("error reading command result: %w", err)
			}
			results = append(results, child.Value)
		}

		return &RedisResult{
			Success: RESP_SUCCESS_WITH_RESULTS,
			Results: results,
		}, nil
	}

	return &RedisResult{
		Success: RESP_UNKNOWN,
		Result:  elt.Value,
	}, fmt.Errorf("unknown command result: %w", err)
}

// coming from https://redis.io/docs/latest/develop/reference/protocol-spec/
const (
	ELEMENT_ARRAY = iota
	ELEMENT_STRING
	ELEMENT_INT
	ELEMENT_SIMPLE
	ELEMENT_ERROR
	ELEMENT_UNKNOWN
)

type Element struct {
	ElementType int
	Value       interface{}
}

func readElement(reader *bufio.Reader) (*Element, error) {
	response, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}
	if response[len(response)-1] == '\n' && response[len(response)-2] == '\r' {
		response = response[:len(response)-2]
	}

	if response[0] == '-' {
		return &Element{
			ElementType: ELEMENT_ERROR,
			Value:       response[1:],
		}, nil
	}

	if response[0] == '+' {
		return &Element{
			ElementType: ELEMENT_SIMPLE,
			Value:       response[1:],
		}, nil
	}

	if response[0] == '$' {
		// length := 0
		// if v,err := strconv.Atoi(response[1:]);err==nil {
		// 	length = v
		// }

		response, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("error reading response: %w", err)
		}
		if response[len(response)-1] == '\n' && response[len(response)-2] == '\r' {
			response = response[:len(response)-2]
		}

		return &Element{
			ElementType: ELEMENT_STRING,
			Value:       response,
		}, nil
	}

	if response[0] == '*' {
		size := 0
		if s, err := strconv.Atoi(response[1:]); err == nil {
			size = s
		}
		return &Element{
			ElementType: ELEMENT_ARRAY,
			Value:       size,
		}, nil
	}
	if response[0] == ':' {
		value := int64(0)
		if v, err := strconv.ParseInt(response[1:], 10, 64); err == nil {
			value = v
		}
		return &Element{
			ElementType: ELEMENT_INT,
			Value:       value,
		}, nil
	}

	return &Element{
		ElementType: ELEMENT_UNKNOWN,
		Value:       response[1:],
	}, nil
}

func (r *ClientImpl) Ping() error {
	conn, err := r.get()
	if err != nil {
		return err
	}
	defer r.put(conn)

	res, err := sendCommand(conn, r.connectionTimeout, "PING")
	if err != nil {
		// let's reset the conn
		conn.Close()
		conn = nil
		return err
	}

	if res.Success != RESP_SUCCESS && res.Result != "PONG" {
		return fmt.Errorf("PING result error: %s", res.Result)
	}
	return nil
}

func (r *ClientImpl) Del(key string) error {
	conn, err := r.get()
	if err != nil {
		return err
	}
	defer r.put(conn)

	res, err := sendCommand(conn, r.connectionTimeout, "DEL", key)
	if err != nil {
		// let's reset the conn
		conn.Close()
		conn = nil
		return err
	}

	if res.Success != RESP_SUCCESS && res.Result != "OK" {
		return fmt.Errorf("DEL result error: %s", res.Result)
	}
	return nil
}
