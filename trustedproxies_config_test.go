package traefik_cluster_ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/juniofirstpay/traefik-cluster-ratelimit/internal/utils"
)

func baseConfig() *Config {
	c := CreateConfig()
	c.Average = 10
	c.Burst = 10
	c.RedisAddress = "127.0.0.1:1" // never connects; New does not dial
	return c
}

// TestTrustedProxiesAndIPStrategyAreMutuallyExclusive — setting both must fail
// at load, not pick a winner. A silent precedence rule leaves an operator
// staring at a `depth` that is quietly doing nothing.
func TestTrustedProxiesAndIPStrategyAreMutuallyExclusive(t *testing.T) {
	c := baseConfig()
	c.TrustedProxies = []string{"10.10.0.0/24"}
	c.SourceCriterion = &utils.SourceCriterion{IPStrategy: &utils.IPStrategy{Depth: 2}}

	_, err := New(context.Background(), http.NotFoundHandler(), c, "test")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected a mutual-exclusion error, got %v", err)
	}
}

// TestEitherAloneIsAccepted — the exclusion must not reject the valid cases.
func TestEitherAloneIsAccepted(t *testing.T) {
	t.Run("trustedProxies alone", func(t *testing.T) {
		c := baseConfig()
		c.TrustedProxies = []string{"10.10.0.0/24"}
		if _, err := New(context.Background(), http.NotFoundHandler(), c, "test"); err != nil {
			t.Fatalf("trustedProxies alone should load: %v", err)
		}
	})
	t.Run("ipStrategy alone", func(t *testing.T) {
		c := baseConfig()
		c.SourceCriterion = &utils.SourceCriterion{IPStrategy: &utils.IPStrategy{Depth: 2}}
		if _, err := New(context.Background(), http.NotFoundHandler(), c, "test"); err != nil {
			t.Fatalf("ipStrategy alone should load: %v", err)
		}
	})
}

// TestBadTrustedProxiesFailsAtLoad — an unparseable CIDR must not be skipped.
func TestBadTrustedProxiesFailsAtLoad(t *testing.T) {
	c := baseConfig()
	c.TrustedProxies = []string{"10.10.0.0/24", "not-a-cidr"}
	if _, err := New(context.Background(), http.NotFoundHandler(), c, "test"); err == nil {
		t.Fatal("expected an unparseable trustedProxies entry to fail at load")
	}
}

// TestTrustedProxiesDrivesTheBucketKey proves the walk feeds the rate-limit
// key, not just the whitelist check — two clients behind the same trusted hop
// must land in different buckets.
func TestTrustedProxiesDrivesTheBucketKey(t *testing.T) {
	c := baseConfig()
	c.TrustedProxies = []string{"10.10.0.0/24"}
	h, err := New(context.Background(), http.NotFoundHandler(), c, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rl := h.(*ClusterRateLimit)

	mk := func(xff string) string {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.10.0.7:52000"
		r.Header.Set("X-Forwarded-For", xff)
		src, _, err := rl.sourceMatcher.Extract(r)
		if err != nil {
			t.Fatalf("Extract: %v", err)
		}
		return src
	}

	if a, b := mk("203.0.113.1"), mk("203.0.113.2"); a == b {
		t.Fatalf("distinct clients shared a bucket key: %q", a)
	}
	if a, b := mk("203.0.113.1, 10.10.0.9"), mk("203.0.113.1"); a != b {
		t.Fatalf("same client keyed differently across chain lengths: %q vs %q", a, b)
	}
}

// TestRequestHostBucketingStillWins — an operator who buckets by something
// that is not an IP keeps that, while the walk still serves the whitelist and
// (later) the published headers. This is the case that would break if the walk
// lived under sourceCriterion.
func TestRequestHostBucketingStillWins(t *testing.T) {
	c := baseConfig()
	c.TrustedProxies = []string{"10.10.0.0/24"}
	c.SourceCriterion = &utils.SourceCriterion{RequestHost: true}

	h, err := New(context.Background(), http.NotFoundHandler(), c, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rl := h.(*ClusterRateLimit)

	r := httptest.NewRequest(http.MethodGet, "http://api.example.test/", nil)
	r.RemoteAddr = "10.10.0.7:52000"
	r.Header.Set("X-Forwarded-For", "203.0.113.1")

	src, _, _ := rl.sourceMatcher.Extract(r)
	if src != "api.example.test" {
		t.Fatalf("requestHost bucketing was overridden by the walk: got %q", src)
	}
	if got := rl.ipStrategy.GetIP(r); got != "203.0.113.1" {
		t.Fatalf("the walk should still derive the client for the whitelist: got %q", got)
	}
}
