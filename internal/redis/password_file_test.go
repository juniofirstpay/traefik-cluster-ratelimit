package redis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeSecret renders a secret file the way a Vault-Agent sidecar would, and
// returns its path.
func writeSecret(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	return path
}

// sawCommand reports whether the server recorded exactly this command. Exact,
// not a prefix: the point of most of these tests is the precise bytes.
func sawCommand(cmds []string, want string) bool {
	for _, cmd := range cmds {
		if cmd == want {
			return true
		}
	}
	return false
}

// TestPasswordFileAuthOnTheWire asserts the exact AUTH command produced from a
// file, in both forms. The file deliberately carries trailing whitespace and a
// newline — what a rendered secret actually looks like — so an untrimmed
// implementation fails here rather than in production, where the only symptom
// is an authentication failure indistinguishable from a wrong password.
func TestPasswordFileAuthOnTheWire(t *testing.T) {
	t.Run("no username -> single-argument form", func(t *testing.T) {
		srv := newRecordingRedis(t, nil)
		path := writeSecret(t, t.TempDir(), "token", "rotating-token \t\n")

		c, err := NewClient(Options{
			Addr: srv.addr(), ConnectionTimeout: 2 * time.Second,
			PasswordFile: path,
		})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		defer c.Close()

		cmds := srv.commands()
		if !sawCommand(cmds, "AUTH rotating-token") {
			t.Fatalf("no trimmed single-argument AUTH observed; got %v", cmds)
		}
	})

	t.Run("username set -> two-argument ACL form", func(t *testing.T) {
		srv := newRecordingRedis(t, nil)
		path := writeSecret(t, t.TempDir(), "token", "rotating-token\n")

		c, err := NewClient(Options{
			Addr: srv.addr(), ConnectionTimeout: 2 * time.Second,
			Username: "gw", PasswordFile: path,
		})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		defer c.Close()

		cmds := srv.commands()
		if !sawCommand(cmds, "AUTH gw rotating-token") {
			t.Fatalf("no two-argument AUTH observed; got %v", cmds)
		}
		if sawCommand(cmds, "AUTH rotating-token") {
			t.Fatal("sent the single-argument AUTH form despite a username being set")
		}
	})
}

// TestPasswordFileIsReadPerDial is the requirement the whole option exists
// for. The token rotates; a value cached at construction would keep being sent
// after the rotation, and every connection made from then on would fail until
// Traefik was restarted.
func TestPasswordFileIsReadPerDial(t *testing.T) {
	srv := newRecordingRedis(t, nil)
	dir := t.TempDir()
	path := writeSecret(t, dir, "token", "token-v1\n")

	c, err := NewClient(Options{
		Addr: srv.addr(), ConnectionTimeout: 2 * time.Second,
		PasswordFile: path,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	if !sawCommand(srv.commands(), "AUTH token-v1") {
		t.Fatalf("first token not used; got %v", srv.commands())
	}

	// Rotate. Dialing directly rather than through Ping: pooled connections
	// are reused, and it is the DIAL that must pick the new token up.
	writeSecret(t, dir, "token", "token-v2\n")
	conn, err := c.(*ClientImpl).newConn()
	if err != nil {
		t.Fatalf("dial after rotation: %v", err)
	}
	defer conn.Close()

	if !sawCommand(srv.commands(), "AUTH token-v2") {
		t.Fatalf("rotated token not picked up on the next dial; got %v", srv.commands())
	}
}

// TestMissingPasswordFileIsRecoverable covers the start-order race: the
// gateway can come up before its Vault-Agent sidecar has rendered the file.
// That must not be fatal at load — the middleware still builds — and it must
// heal by itself once the file appears, without a restart.
func TestMissingPasswordFileIsRecoverable(t *testing.T) {
	srv := newRecordingRedis(t, nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "not-yet-rendered")

	c, err := NewClient(Options{
		Addr: srv.addr(), ConnectionTimeout: 2 * time.Second,
		PasswordFile: path,
	})
	if err != nil {
		t.Fatalf("a missing password file must not fail client construction: %v", err)
	}
	defer c.Close()

	if err := c.Ping(); err == nil {
		t.Fatal("expected the dial to fail while the password file is absent")
	} else if !strings.Contains(err.Error(), "redisPasswordFile") {
		t.Fatalf("error should name the option that failed, got %v", err)
	}
	if len(srv.commands()) != 0 {
		t.Fatalf("connected without a resolvable secret; got %v", srv.commands())
	}

	// The sidecar renders it.
	writeSecret(t, dir, "not-yet-rendered", "late-token\n")
	if err := c.Ping(); err != nil {
		t.Fatalf("Ping after the file appeared: %v", err)
	}
	if !sawCommand(srv.commands(), "AUTH late-token") {
		t.Fatalf("did not authenticate with the rendered token; got %v", srv.commands())
	}
}

// TestEmptyPasswordFileIsAnError — a half-written render must not become a
// connection that silently skips AUTH.
func TestEmptyPasswordFileIsAnError(t *testing.T) {
	srv := newRecordingRedis(t, nil)
	path := writeSecret(t, t.TempDir(), "token", "\n  \n")

	c, err := NewClient(Options{
		Addr: srv.addr(), ConnectionTimeout: 2 * time.Second,
		PasswordFile: path,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	if err := c.Ping(); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("expected an empty-file rejection, got %v", err)
	}
	if len(srv.commands()) != 0 {
		t.Fatalf("connected on an empty secret; got %v", srv.commands())
	}
}

// TestPasswordAndPasswordFileAreMutuallyExclusive — two answers to the same
// question. Picking one silently is how a rotating token gets ignored in
// favour of a stale literal with nothing in the logs to say so.
func TestPasswordAndPasswordFileAreMutuallyExclusive(t *testing.T) {
	_, err := NewClient(Options{
		Addr: "127.0.0.1:1", ConnectionTimeout: time.Second,
		Password: "literal", PasswordFile: "/run/secrets/token",
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected a mutual-exclusion error, got %v", err)
	}
}

// TestReadPasswordFileTrims pins the trimming exactly, which the wire tests
// can only assert indirectly, and checks that the secret is never echoed into
// an error message.
func TestReadPasswordFileTrims(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, contents, want string
	}{
		{"trailing newline", "s3cret\n", "s3cret"},
		{"crlf", "s3cret\r\n", "s3cret"},
		{"trailing spaces and tab", "s3cret \t ", "s3cret"},
		{"leading whitespace too", "\n s3cret \n", "s3cret"},
		{"no whitespace at all", "s3cret", "s3cret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readPasswordFile(writeSecret(t, dir, "token", tc.contents))
			if err != nil {
				t.Fatalf("readPasswordFile: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("error never carries the secret", func(t *testing.T) {
		// Unreadable rather than absent: the read fails with the contents on
		// disk, which is the case where they could leak into the message.
		path := writeSecret(t, dir, "unreadable", "s3cret\n")
		if err := os.Chmod(path, 0o000); err != nil {
			t.Skipf("cannot make the file unreadable: %v", err)
		}
		defer os.Chmod(path, 0o600)
		if os.Geteuid() == 0 {
			t.Skip("running as root; the mode is not enforced")
		}

		_, err := readPasswordFile(path)
		if err == nil {
			t.Fatal("expected an unreadable file to fail")
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Fatalf("error leaked the secret: %v", err)
		}
	})
}
