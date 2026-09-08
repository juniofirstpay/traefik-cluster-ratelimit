package traefik_cluster_ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/juniofirstpay/traefik-cluster-ratelimit/internal/utils"
)

// captured records the headers the backend actually received.
func captured(t *testing.T, cfg *Config, set map[string]string) http.Header {
	t.Helper()
	return capturedFrom(t, cfg, "10.10.0.7:52000", set)
}

// capturedFrom is the same with an explicit socket peer.
func capturedFrom(t *testing.T, cfg *Config, remote string, set map[string]string) http.Header {
	t.Helper()
	var got http.Header
	next := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		rw.WriteHeader(http.StatusOK)
	})
	h, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for k, v := range set {
		r.Header.Set(k, v)
	}
	h.ServeHTTP(httptest.NewRecorder(), r)
	return got
}

// TestDestroysForwardedAndXRealIP is the point of the change.
func TestDestroysForwardedAndXRealIP(t *testing.T) {
	cfg := baseConfig()
	cfg.TrustedProxies = []string{"10.10.0.0/24"}
	cfg.FailureMode = FailureModeOpen // let the request reach the backend

	got := captured(t, cfg, map[string]string{
		"Forwarded":       "for=1.2.3.4",
		"X-Real-IP":       "9.9.9.9",
		"X-Forwarded-For": "203.0.113.9",
	})

	if v := got.Get("Forwarded"); v != "" {
		t.Fatalf("Forwarded survived: %q", v)
	}
	if v := got.Get("X-Real-IP"); v != "" {
		t.Fatalf("X-Real-IP survived: %q", v)
	}
	if v := got.Get("X-Forwarded-For"); v != "203.0.113.9" {
		t.Fatalf("X-Forwarded-For must be left intact, got %q", v)
	}
}

// TestDestructionIsUnconditional — an unlimited route still gets it. Whether a
// route is rate limited says nothing about whether its backend should be handed
// a client-settable address header.
func TestDestructionIsUnconditional(t *testing.T) {
	cfg := baseConfig()
	cfg.TrustedProxies = []string{"10.10.0.0/24"}
	cfg.Average = 0 // unlimited: ServeHTTP returns early

	got := captured(t, cfg, map[string]string{"Forwarded": "for=1.2.3.4"})
	if v := got.Get("Forwarded"); v != "" {
		t.Fatalf("an unlimited route leaked Forwarded: %q", v)
	}
}

// TestDestructionNotTiedToTrustedProxies is the coupling guard. Destruction
// must NOT depend on the derivation config: someone removing or changing
// trustedProxies must not silently switch off a separate security control.
func TestDestructionNotTiedToTrustedProxies(t *testing.T) {
	cfg := baseConfig()
	cfg.SourceCriterion = &utils.SourceCriterion{IPStrategy: &utils.IPStrategy{}} // no trustedProxies
	cfg.FailureMode = FailureModeOpen

	got := captured(t, cfg, map[string]string{"Forwarded": "for=1.2.3.4", "X-Real-IP": "9.9.9.9"})
	if got.Get("Forwarded") != "" || got.Get("X-Real-IP") != "" {
		t.Fatal("destruction stopped when trustedProxies was absent — the two must not be coupled")
	}
}

// TestDerivationMustBeExplicit — no silent RemoteAddr fallback. Deleting
// trustedProxies has to fail loudly at load, not degrade quietly.
func TestDerivationMustBeExplicit(t *testing.T) {
	cfg := baseConfig() // neither trustedProxies nor ipStrategy
	_, err := New(context.Background(), http.NotFoundHandler(), cfg, "test")
	if err == nil || !strings.Contains(err.Error(), "derivation must be configured explicitly") {
		t.Fatalf("expected an explicit-derivation error, got %v", err)
	}
}

// TestEmptyIPStrategyIsTheExplicitRemoteAddr — the escape hatch still exists,
// it just has to be written down.
func TestEmptyIPStrategyIsTheExplicitRemoteAddr(t *testing.T) {
	cfg := baseConfig()
	cfg.SourceCriterion = &utils.SourceCriterion{IPStrategy: &utils.IPStrategy{}}
	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err != nil {
		t.Fatalf("an empty ipStrategy should be accepted as an explicit RemoteAddr: %v", err)
	}
}
