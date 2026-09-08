package traefik_cluster_ratelimit

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// authConfig is baseConfig with a derivation chosen, so a failure here is
// about the credential and nothing else.
func authConfig() *Config {
	c := baseConfig()
	c.TrustedProxies = []string{"10.10.0.0/24"}
	return c
}

// TestRedisPasswordAndPasswordFileAreMutuallyExclusive — two answers to the
// same question. A precedence rule would silently ignore one of them, and the
// one being ignored would be the rotating token.
func TestRedisPasswordAndPasswordFileAreMutuallyExclusive(t *testing.T) {
	c := authConfig()
	c.RedisPassword = "literal"
	c.RedisPasswordFile = "/run/secrets/redis-token"

	_, err := New(context.Background(), http.NotFoundHandler(), c, "test")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected a mutual-exclusion error, got %v", err)
	}
}

// TestRedisPasswordConflictIsSeenBeforeEnvIndirection — the check runs on the
// values as written. Resolving '$REDIS_PASSWORD' first would blank the literal
// whenever the variable happens to be unset, so the same config would be
// rejected on one box and quietly accepted on another.
func TestRedisPasswordConflictIsSeenBeforeEnvIndirection(t *testing.T) {
	c := authConfig()
	c.RedisPassword = "$THIS_VARIABLE_IS_NOT_SET_ANYWHERE"
	c.RedisPasswordFile = "/run/secrets/redis-token"

	_, err := New(context.Background(), http.NotFoundHandler(), c, "test")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected a mutual-exclusion error, got %v", err)
	}
}

// TestEitherCredentialAloneIsAccepted — the exclusion must not reject the two
// valid configurations.
func TestEitherCredentialAloneIsAccepted(t *testing.T) {
	t.Run("password alone", func(t *testing.T) {
		c := authConfig()
		c.RedisPassword = "literal"
		if _, err := New(context.Background(), http.NotFoundHandler(), c, "test"); err != nil {
			t.Fatalf("redisPassword alone should load: %v", err)
		}
	})
	t.Run("password file alone", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(path, []byte("rotating-token\n"), 0o600); err != nil {
			t.Fatalf("write secret: %v", err)
		}
		c := authConfig()
		c.RedisPasswordFile = path
		if _, err := New(context.Background(), http.NotFoundHandler(), c, "test"); err != nil {
			t.Fatalf("redisPasswordFile alone should load: %v", err)
		}
	})
}

// TestRedisPasswordFileIsNotReadAtLoad — the middleware must build even when
// the file is not there yet. A gateway whose Vault-Agent sidecar has not
// rendered the token has to come up anyway; failing at load would drop the
// router and take the route out entirely, and it would stay out, because
// nothing re-runs New until the configuration changes.
func TestRedisPasswordFileIsNotReadAtLoad(t *testing.T) {
	c := authConfig()
	c.RedisPasswordFile = filepath.Join(t.TempDir(), "not-yet-rendered")

	if _, err := New(context.Background(), http.NotFoundHandler(), c, "test"); err != nil {
		t.Fatalf("an absent password file must not fail the load: %v", err)
	}
}
