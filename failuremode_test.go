package traefik_cluster_ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/juniofirstpay/traefik-cluster-ratelimit/internal/ip"
	"github.com/juniofirstpay/traefik-cluster-ratelimit/internal/redis"
)

// unreachableClient stands in for a Redis/Valkey that cannot be reached: every
// script run errors, which is what the limiter sees during an outage.
type unreachableClient struct{}

func (unreachableClient) Close()               {}
func (unreachableClient) Ping() error          { return fmt.Errorf("unreachable") }
func (unreachableClient) Del(key string) error { return fmt.Errorf("unreachable") }
func (unreachableClient) NewScript(s string) redis.Script {
	return failingScript{}
}

type failingScript struct{}

func (failingScript) Run(keys []string, args ...interface{}) (interface{}, error) {
	return nil, fmt.Errorf("unreachable")
}

// newLimiterUnderOutage builds the middleware with a store that always fails,
// which is what the limiter sees during a Redis/Valkey outage.
func newLimiterUnderOutage(mode string) http.Handler {
	next := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	return &ClusterRateLimit{
		next:          next,
		limiter:       NewLimiter(unreachableClient{}, "test", 3, 15),
		name:          "test",
		average:       10,
		burst:         10,
		period:        1,
		sourceMatcher: fixedSource{},
		ipStrategy:    &ip.RemoteAddrStrategy{},
		ipv6Subnet:    64,
		failureMode:   mode,
		retryAfter:    15,
	}
}

// fixedSource keeps these tests focused on the failure mode rather than on
// source extraction.
type fixedSource struct{}

func (fixedSource) Extract(req *http.Request) (string, int64, error) {
	return "1.2.3.4", 1, nil
}

// TestFailClosedRejectsWith503 is the point of the change: when the store is
// unreachable, the request must not pass.
func TestFailClosedRejectsWith503(t *testing.T) {
	h := newLimiterUnderOutage(FailureModeClosed)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
	if got := rec.Header().Get("retry-after"); got != "15" {
		t.Fatalf("want Retry-After 15 (the breaker reattempt period), got %q", got)
	}
}

// TestFailOpenStillPasses proves the opt-out works and upstream behaviour is
// still reachable.
func TestFailOpenStillPasses(t *testing.T) {
	h := newLimiterUnderOutage(FailureModeOpen)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 (request passed through), got %d", rec.Code)
	}
}

// TestDefaultsToClosed is the divergence from upstream, asserted rather than
// documented: a config that omits failureMode must get the safe posture.
func TestDefaultsToClosed(t *testing.T) {
	cfg := CreateConfig()
	cfg.Average = 10
	cfg.Burst = 10
	cfg.RedisAddress = "127.0.0.1:1" // never connects; New must not dial
	cfg.TrustedProxies = []string{"10.10.0.0/24"}
	next := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {})

	h, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := h.(*ClusterRateLimit).failureMode; got != FailureModeClosed {
		t.Fatalf("omitted failureMode must default to %q, got %q", FailureModeClosed, got)
	}
}

// TestRejectsUnknownFailureMode — a typo must not silently pick a posture.
func TestRejectsUnknownFailureMode(t *testing.T) {
	cfg := CreateConfig()
	cfg.Average = 10
	cfg.Burst = 10
	cfg.TrustedProxies = []string{"10.10.0.0/24"} // so the failure is unambiguous
	cfg.FailureMode = "clsoed"                    // typo
	next := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {})

	// Assert on the message, not merely that an error occurred: with a
	// derivation now mandatory, an under-specified config errors for a
	// DIFFERENT reason and this test would pass without proving anything.
	_, err := New(context.Background(), next, cfg, "test")
	if err == nil || !strings.Contains(err.Error(), "failureMode") {
		t.Fatalf("expected a typo'd failureMode to be rejected at load, got %v", err)
	}
}
