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

// TestIPv6SubnetBounds — the range is what stops the option becoming an
// off-switch. 128 is the address itself, i.e. no aggregation.
func TestIPv6SubnetBounds(t *testing.T) {
	for _, bad := range []int{128, 65, 31, 1, -1} {
		c := baseConfig()
		c.TrustedProxies = []string{"10.10.0.0/24"}
		c.IPv6Subnet = bad
		if _, err := New(context.Background(), http.NotFoundHandler(), c, "test"); err == nil {
			t.Fatalf("ipv6Subnet %d should be rejected at load", bad)
		}
	}
	for _, ok := range []int{32, 48, 56, 64} {
		c := baseConfig()
		c.TrustedProxies = []string{"10.10.0.0/24"}
		c.IPv6Subnet = ok
		if _, err := New(context.Background(), http.NotFoundHandler(), c, "test"); err != nil {
			t.Fatalf("ipv6Subnet %d should be accepted: %v", ok, err)
		}
	}
}

// TestIPv6SubnetDefaults — omitting it must aggregate, not disable.
func TestIPv6SubnetDefaults(t *testing.T) {
	c := baseConfig()
	c.TrustedProxies = []string{"10.10.0.0/24"}
	if _, err := New(context.Background(), http.NotFoundHandler(), c, "test"); err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.IPv6Subnet != 64 {
		t.Fatalf("omitted ipv6Subnet must default to 64, got %d", c.IPv6Subnet)
	}
}

// TestIPv6ClientsShareABucket drives it through the real source extractor: a
// rotating IPv6 client must not get a fresh bucket per address.
func TestIPv6ClientsShareABucket(t *testing.T) {
	c := baseConfig()
	c.TrustedProxies = []string{"10.10.0.0/24"}
	h, err := New(context.Background(), http.NotFoundHandler(), c, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rl := h.(*ClusterRateLimit)

	key := func(xff string) string {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.10.0.7:52000"
		r.Header.Set("X-Forwarded-For", xff)
		k, _, err := rl.sourceMatcher.Extract(r)
		if err != nil {
			t.Fatalf("Extract: %v", err)
		}
		return k
	}

	a := key("2001:db8:cafe:1::1")
	b := key("2001:db8:cafe:1:f8a2:9c31:0e77:4b21")
	if a != b {
		t.Fatalf("a rotating IPv6 client got two buckets: %q and %q", a, b)
	}
	if c := key("2001:db8:cafe:2::1"); c == a {
		t.Fatalf("a different /64 shared the bucket: %q", c)
	}
	// IPv4 must be untouched by any of this.
	if k := key("203.0.113.9"); k != "203.0.113.9" {
		t.Fatalf("IPv4 key was aggregated: %q", k)
	}
	// ...and the whitelist check still sees the FULL address, not the subnet.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.10.0.7:52000"
	r.Header.Set("X-Forwarded-For", "2001:db8:cafe:1::1")
	if got := rl.ipStrategy.GetIP(r); got != "2001:db8:cafe:1::1" {
		t.Fatalf("identity should stay the full address, got %q", got)
	}
}
