package traefik_cluster_ratelimit

import (
	"net/http"
	"testing"

	"github.com/juniofirstpay/traefik-cluster-ratelimit/internal/utils"
)

func publishedFor(t *testing.T, cfg *Config, remote, xff string) http.Header {
	t.Helper()
	set := map[string]string{}
	if xff != "" {
		set["X-Forwarded-For"] = xff
	}
	return capturedFrom(t, cfg, remote, set)
}

// TestPublishesTheDerivedAddress — the identity, the provenance and the
// rate-limit key, all three.
func TestPublishesTheDerivedAddress(t *testing.T) {
	cfg := baseConfig()
	cfg.TrustedProxies = []string{"10.10.0.0/24"}
	cfg.FailureMode = FailureModeOpen

	got := publishedFor(t, cfg, "10.10.0.7:52000", "203.0.113.9")

	if v := got.Get(HeaderClientIP); v != "203.0.113.9" {
		t.Fatalf("%s = %q, want the derived client", HeaderClientIP, v)
	}
	if v := got.Get(HeaderClientIPSource); v != "xff" {
		t.Fatalf("%s = %q, want xff", HeaderClientIPSource, v)
	}
	if v := got.Get(HeaderClientSubnet); v != "203.0.113.9/32" {
		t.Fatalf("%s = %q, want CIDR notation", HeaderClientSubnet, v)
	}
}

// TestSubnetIsCIDRForIPv6 — the prefix length is what distinguishes an
// aggregate from a literal address in an audit trail.
func TestSubnetIsCIDRForIPv6(t *testing.T) {
	cfg := baseConfig()
	cfg.TrustedProxies = []string{"10.10.0.0/24"}
	cfg.FailureMode = FailureModeOpen

	got := publishedFor(t, cfg, "10.10.0.7:52000", "2001:db8:cafe:1:f8a2:9c31:0e77:4b21")

	if v := got.Get(HeaderClientIP); v != "2001:db8:cafe:1:f8a2:9c31:0e77:4b21" {
		t.Fatalf("identity must be the FULL address, got %q", v)
	}
	if v := got.Get(HeaderClientSubnet); v != "2001:db8:cafe:1::/64" {
		t.Fatalf("%s = %q, want 2001:db8:cafe:1::/64", HeaderClientSubnet, v)
	}
}

// TestProvenanceReportsTheExit — the value worth alerting on is a peer that
// did not traverse a trusted proxy.
func TestProvenanceReportsTheExit(t *testing.T) {
	cfg := baseConfig()
	cfg.TrustedProxies = []string{"10.10.0.0/24"}
	cfg.FailureMode = FailureModeOpen

	cases := []struct{ name, remote, xff, want string }{
		{"normal", "10.10.0.7:52000", "203.0.113.9", "xff"},
		{"peer did not traverse a trusted proxy", "198.51.100.5:41000", "203.0.113.9", "peer-untrusted"},
		{"trusted peer, no header", "10.10.0.7:52000", "", "peer-no-xff"},
		{"malformed entry", "10.10.0.7:52000", "203.0.113.9, unknown", "peer-malformed"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := publishedFor(t, cfg, tc.remote, tc.xff)
			if v := got.Get(HeaderClientIPSource); v != tc.want {
				t.Fatalf("%s = %q, want %q", HeaderClientIPSource, v, tc.want)
			}
		})
	}
}

// TestInboundCopiesAreDestroyed is what makes the published values worth
// trusting: a client cannot supply them.
func TestInboundCopiesAreDestroyed(t *testing.T) {
	cfg := baseConfig()
	cfg.TrustedProxies = []string{"10.10.0.0/24"}
	cfg.FailureMode = FailureModeOpen

	got := capturedFrom(t, cfg, "10.10.0.7:52000", map[string]string{
		"X-Forwarded-For":    "203.0.113.9",
		HeaderClientIP:       "1.2.3.4",
		HeaderClientIPSource: "xff",
		HeaderClientSubnet:   "1.2.3.4/32",
	})

	if v := got.Get(HeaderClientIP); v != "203.0.113.9" {
		t.Fatalf("a client-supplied %s survived: %q", HeaderClientIP, v)
	}
	if v := got.Get(HeaderClientSubnet); v != "203.0.113.9/32" {
		t.Fatalf("a client-supplied %s survived: %q", HeaderClientSubnet, v)
	}
}

// TestPublishesOnUnlimitedRoutes — an unlimited route still tells its backend
// who the caller is.
func TestPublishesOnUnlimitedRoutes(t *testing.T) {
	cfg := baseConfig()
	cfg.TrustedProxies = []string{"10.10.0.0/24"}
	cfg.Average = 0

	got := publishedFor(t, cfg, "10.10.0.7:52000", "203.0.113.9")
	if v := got.Get(HeaderClientIP); v != "203.0.113.9" {
		t.Fatalf("unlimited route did not publish: %q", v)
	}
}

// TestNoProvenanceWithoutTheWalk — depth and pool selection have no notion of
// which exit they took, so the header is omitted rather than invented.
func TestNoProvenanceWithoutTheWalk(t *testing.T) {
	cfg := baseConfig()
	cfg.SourceCriterion = &utils.SourceCriterion{IPStrategy: &utils.IPStrategy{Depth: 1}}
	cfg.FailureMode = FailureModeOpen

	got := publishedFor(t, cfg, "10.10.0.7:52000", "203.0.113.9")
	if v := got.Get(HeaderClientIP); v != "203.0.113.9" {
		t.Fatalf("identity should still be published: %q", v)
	}
	if v := got.Get(HeaderClientIPSource); v != "" {
		t.Fatalf("provenance should be omitted without the walk, got %q", v)
	}
}
