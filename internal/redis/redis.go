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
	authFile          string
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
	// Password is the AUTH secret, as a literal.
	Password string
	// PasswordFile is a path whose CONTENTS are the AUTH secret, re-read on
	// every dial rather than once here. It is how a rotating credential is
	// carried — see authSecret for why the read cannot be hoisted into
	// NewClient. Mutually exclusive with Password.
	PasswordFile string
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

	// A literal and a file are two answers to the same question. The plugin
	// layer rejects the pair first, on the values as written; this keeps the
	// invariant total for any other caller of Options, because the alternative
	// here is a silent precedence rule — exactly the failure this option
	// exists to avoid, where the operator's rotating token is ignored in
	// favour of a stale literal and nothing says so.
	if o.Password != "" && o.PasswordFile != "" {
		return nil, errors.New("redis: redisPassword and redisPasswordFile are mutually exclusive")
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
		authFile:          o.PasswordFile,
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
	// Resolve the secret BEFORE dialing. When it comes from a file the read
	// can fail, and failing here costs nothing to unwind: no socket is open
	// yet, and there is no point completing a TCP connect and a TLS handshake
	// to a server we already know we cannot authenticate to.
	secret, err := r.authSecret()
	if err != nil {
		return nil, err
	}

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

	if secret != "" {
		// Two-argument AUTH when a username is configured (Redis 6+ ACLs),
		// single-argument otherwise. The username is a stable identity, so it
		// stays a literal even when the password rotates on disk.
		var resp *RedisResult
		if r.username != "" {
			resp, err = sendCommand(conn, r.connectionTimeout, "AUTH", r.username, secret)
		} else {
			resp, err = sendCommand(conn, r.connectionTimeout, "AUTH", secret)
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

// authSecret is the AUTH argument for THIS dial. A literal password is handed
// straight back; a password FILE is re-read every time.
//
// Re-reading is the whole point of the file form, not an oversight. The
// credential it holds is a rotating token — an ElastiCache/Valkey auth token
// re-rendered by a Vault-Agent sidecar — so a value captured once in NewClient
// goes stale at the first rotation and every connection after it fails, with
// no way back short of restarting Traefik. Reading per dial also makes the
// start-order race survivable: a gateway that comes up BEFORE the sidecar has
// rendered the file still loads (pool prepopulation tolerates dial failures),
// and the first request that misses the pool re-reads the file and connects.
//
// Deliberately no cache and no last-good fallback, unlike the sibling
// gwvalidator plugin that inspired this: a dial here already pays a TCP
// connect, possibly a TLS handshake, and two round trips, next to which one
// small read is noise — and going without removes both the staleness window
// and the lock. A read that fails fails only this dial, which is precisely
// what an unreachable Redis already is: the breaker counts it and failureMode
// decides.
func (r *ClientImpl) authSecret() (string, error) {
	if r.authFile == "" {
		return r.auth, nil
	}
	return readPasswordFile(r.authFile)
}

// readPasswordFile reads the AUTH argument from disk, trimmed of surrounding
// whitespace. The trim is not cosmetic: a rendered secret file ends in a
// newline, and a token carrying a stray \n is refused by AUTH with the same
// answer as a genuinely wrong credential, so the config looks right, the file
// looks right, and the only symptom is a connection that will not authenticate.
//
// An empty file is an error rather than a connection that silently skips AUTH:
// something asked for a password, and connecting without one is not the milder
// failure. It is also the shape of a half-written render, which the next dial
// will get right. The contents never appear in the returned error.
func readPasswordFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("redis: reading redisPasswordFile " + path + ": " + err.Error())
	}
	secret := strings.TrimSpace(string(raw))
	if secret == "" {
		return "", errors.New("redis: redisPasswordFile " + path + " is empty")
	}
	return secret, nil
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
