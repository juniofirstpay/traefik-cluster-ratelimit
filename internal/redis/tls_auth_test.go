package redis

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingRedis is a minimal RESP server that answers +OK to everything and
// records the commands it received, so a test can assert on the exact AUTH
// form that went over the wire. It listens over TLS when tlsCfg is non-nil.
type recordingRedis struct {
	ln   net.Listener
	mu   sync.Mutex
	cmds []string
}

func newRecordingRedis(t *testing.T, tlsCfg *tls.Config) *recordingRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	r := &recordingRedis{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return r
}

// serve reads RESP arrays and replies +OK to each.
func (r *recordingRedis) serve(c net.Conn) {
	defer c.Close()
	rd := bufio.NewReader(c)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if !strings.HasPrefix(line, "*") {
			continue
		}
		var n int
		fmt.Sscanf(line, "*%d", &n)
		parts := make([]string, 0, n)
		for i := 0; i < n; i++ {
			if _, err := rd.ReadString('\n'); err != nil { // $len
				return
			}
			arg, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			parts = append(parts, strings.TrimRight(arg, "\r\n"))
		}
		r.mu.Lock()
		r.cmds = append(r.cmds, strings.Join(parts, " "))
		r.mu.Unlock()
		c.Write([]byte("+OK\r\n"))
	}
}

func (r *recordingRedis) addr() string { return r.ln.Addr().String() }

func (r *recordingRedis) commands() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.cmds))
	copy(out, r.cmds)
	return out
}

// selfSignedFor mints an ECDSA leaf valid for 127.0.0.1 and writes the CA PEM
// to a temp file, returning the server config and that path.
func selfSignedFor(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-redis"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}}}, caPath
}

// TestTLSHandshakeAndCAVerification proves the client actually negotiates TLS
// against a TLS-only listener, and that it verifies against the supplied CA.
func TestTLSHandshakeAndCAVerification(t *testing.T) {
	srvCfg, caPath := selfSignedFor(t)
	srv := newRecordingRedis(t, srvCfg)

	c, err := NewClient(Options{
		Addr:              srv.addr(),
		ConnectionTimeout: 2 * time.Second,
		CACertFile:        caPath, // implies TLS
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	if err := c.Ping(); err != nil {
		t.Fatalf("Ping over TLS: %v", err)
	}
}

// TestTLSRejectsUntrustedServer is the negative half: without the CA, the
// handshake must fail. If this ever passes, verification is not happening.
func TestTLSRejectsUntrustedServer(t *testing.T) {
	srvCfg, _ := selfSignedFor(t)
	srv := newRecordingRedis(t, srvCfg)

	c, err := NewClient(Options{
		Addr:              srv.addr(),
		ConnectionTimeout: 2 * time.Second,
		TLS:               true, // TLS on, but no CA -> system roots -> untrusted
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	if err := c.Ping(); err == nil {
		t.Fatal("expected the handshake to be rejected against an untrusted certificate")
	}
}

// TestPlaintextStillWorks guards against a regression: a client with no TLS
// settings must not attempt a handshake.
func TestPlaintextStillWorks(t *testing.T) {
	srv := newRecordingRedis(t, nil)
	c, err := NewClient(Options{Addr: srv.addr(), ConnectionTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()
	if err := c.Ping(); err != nil {
		t.Fatalf("Ping over plaintext: %v", err)
	}
}

// TestAuthFormOnTheWire asserts the exact AUTH command emitted for each of the
// two forms. This is the point of the change, so it is asserted on the wire
// rather than inferred from configuration.
func TestAuthFormOnTheWire(t *testing.T) {
	t.Run("username set -> two-argument ACL form", func(t *testing.T) {
		srv := newRecordingRedis(t, nil)
		c, err := NewClient(Options{
			Addr: srv.addr(), ConnectionTimeout: 2 * time.Second,
			Username: "gw", Password: "s3cret",
		})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		defer c.Close()

		var found bool
		for _, cmd := range srv.commands() {
			if cmd == "AUTH gw s3cret" {
				found = true
			}
			if cmd == "AUTH s3cret" {
				t.Fatal("sent the single-argument AUTH form despite a username being set")
			}
		}
		if !found {
			t.Fatalf("no two-argument AUTH observed; got %v", srv.commands())
		}
	})

	t.Run("no username -> single-argument form, unchanged", func(t *testing.T) {
		srv := newRecordingRedis(t, nil)
		c, err := NewClient(Options{
			Addr: srv.addr(), ConnectionTimeout: 2 * time.Second,
			Password: "s3cret",
		})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		defer c.Close()

		var found bool
		for _, cmd := range srv.commands() {
			if cmd == "AUTH s3cret" {
				found = true
			}
		}
		if !found {
			t.Fatalf("no single-argument AUTH observed; got %v", srv.commands())
		}
	})
}

// TestBuildTLSConfigRejectsHalfKeypair — a half-supplied keypair is a mistake,
// not a request to fall back.
func TestBuildTLSConfigRejectsHalfKeypair(t *testing.T) {
	_, err := NewClient(Options{
		Addr: "127.0.0.1:6379", ConnectionTimeout: time.Second,
		ClientCertFile: "/nonexistent/cert.pem",
	})
	if err == nil || !strings.Contains(err.Error(), "must be set together") {
		t.Fatalf("expected a half-keypair rejection, got %v", err)
	}
}

// TestServerNameDerivedFromAddr — ServerName is mandatory for tls.Client, and
// an address with no host cannot supply one.
func TestServerNameDerivedFromAddr(t *testing.T) {
	if _, err := NewClient(Options{
		Addr: ":6379", ConnectionTimeout: time.Second, TLS: true,
	}); err == nil || !strings.Contains(err.Error(), "redisServerName") {
		t.Fatalf("expected a server-name derivation failure, got %v", err)
	}
}
