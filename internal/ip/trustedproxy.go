package ip

import (
	"net"
	"net/http"
	"strconv"
	"strings"
)

// Source records which exit of the walk produced an address. A caller can
// collapse these; it cannot recover them if the walk discards the distinction.
type Source string

const (
	// SourceXFF is the normal path: the walk stopped at the first entry that
	// is not one of ours.
	SourceXFF Source = "xff"
	// SourcePeerUntrusted means the socket peer is not in the trusted set, so
	// no forwarded header was read at all. Something reached this proxy
	// without traversing the load balancer — worth alerting on.
	SourcePeerUntrusted Source = "peer-untrusted"
	// SourcePeerNoXFF is a trusted peer with no X-Forwarded-For: health checks
	// and internal callers.
	SourcePeerNoXFF Source = "peer-no-xff"
	// SourcePeerAllTrusted means every entry in the header was ours.
	SourcePeerAllTrusted Source = "peer-all-trusted"
	// SourcePeerMalformed means the walk aborted on an entry it could not
	// parse, or on an implausibly long header.
	SourcePeerMalformed Source = "peer-malformed"
)

// maxXFFEntries bounds the walk. Traefik caps total header size well below
// this, so it is a belt-and-braces guard against a parser DoS rather than the
// primary control. A header longer than this is not a real proxy chain.
const maxXFFEntries = 32

// Resolver is a Strategy that can also report HOW it arrived at an address.
// Only the trusted-proxy walk can: depth and pool selection have no notion of
// which exit they took.
type Resolver interface {
	Resolve(req *http.Request) (string, Source)
}

// TrustedProxyStrategy derives the client address by walking X-Forwarded-For
// from right to left, skipping addresses in a trusted set and stopping at the
// first that is not. It is the algorithm nginx (real_ip_recursive), Apache
// (mod_remoteip), Rails (trusted_proxies) and Envoy (xff_num_trusted_hops) all
// implement.
//
// Unlike DepthStrategy it is position-independent: the same configuration is
// correct at the edge, where the client is the last entry, and at a backend one
// hop further in, where it is the second-to-last. Unlike PoolStrategy it
// anchors on the socket peer, so a request that did not arrive through a
// trusted proxy has its forwarded headers ignored entirely rather than
// believed.
type TrustedProxyStrategy struct {
	Checker *Checker
}

// GetIP satisfies Strategy. Callers that need the provenance use Resolve.
func (s *TrustedProxyStrategy) GetIP(req *http.Request) string {
	addr, _ := s.Resolve(req)
	return addr
}

// Resolve returns the derived client address and the exit that produced it.
// It never returns an empty string: the socket peer is the floor. An empty
// string is a valid map key, so returning one would silently collapse every
// affected request into a single rate-limit bucket.
func (s *TrustedProxyStrategy) Resolve(req *http.Request) (string, Source) {
	peer := remoteAddrIP(req)

	if s.Checker == nil {
		return peer, SourcePeerUntrusted
	}
	if trusted, err := s.Checker.Contains(peer); err != nil || !trusted {
		// The request did not arrive through a proxy we trust, so nothing it
		// carries about its own origin is worth reading.
		return peer, SourcePeerUntrusted
	}

	raw := req.Header.Get(xForwardedFor)
	if strings.TrimSpace(raw) == "" {
		return peer, SourcePeerNoXFF
	}

	entries := strings.Split(raw, ",")
	if len(entries) > maxXFFEntries {
		return peer, SourcePeerMalformed
	}

	for i := len(entries) - 1; i >= 0; i-- {
		candidate, ok := normaliseEntry(entries[i])
		if !ok {
			// Stop rather than skip. Skipping a malformed entry would let a
			// client hide a hop behind garbage and shift which address the
			// walk lands on.
			return peer, SourcePeerMalformed
		}
		if trusted, err := s.Checker.Contains(candidate); err == nil && trusted {
			continue
		}
		return candidate, SourceXFF
	}

	return peer, SourcePeerAllTrusted
}

// normaliseEntry trims one X-Forwarded-For element down to a bare IP address,
// rejecting anything that is not one.
//
// It has to cope with: a plain address; an address with a port, which an ALB
// emits when routing.http.xff_client_port.enabled is set; a bracketed IPv6
// address with a port; and RFC 7239's obfuscated and "unknown" identifiers,
// which are legal in a Forwarded header and meaningless as a rate-limit key.
func normaliseEntry(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}

	// "[2001:db8::1]:443" and "1.2.3.4:5678" split; a bare IPv6 address has
	// too many colons and does not, which is the signal to use it as-is.
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")

	// ParseIP rejects "unknown", "_hidden" and every other obfuscated token.
	if net.ParseIP(s) == nil {
		return "", false
	}
	return s, true
}

// remoteAddrIP strips the port from RemoteAddr, handling IPv6 correctly.
func remoteAddrIP(req *http.Request) string {
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		return host
	}
	return req.RemoteAddr
}

// IPv6 aggregation bounds. The floor keeps a prefix from merging unrelated
// networks; the ceiling is what makes this impossible to switch off.
//
// /64 is the safe default because it is the smallest allocation that exists —
// SLAAC requires 64 bits for the host portion, so every client controls at
// least one /64 and aggregating there can never merge two customers. Sites are
// often delegated more (a /56 or /48 is ordinary for home and business
// connections), so a deployment that knows its upstream allocation policy can
// aggregate wider and count a whole site as one client.
//
// 128 is deliberately NOT accepted. A /128 is the address itself, i.e. no
// aggregation, i.e. the bypass this exists to close: OS privacy extensions
// (RFC 4941) rotate the low bits by default, so per-address limiting does not
// constrain an IPv6 client at all. Allowing 128 would make the option an
// off-switch, and an off-switch is what turns a control into a suggestion.
const (
	MinIPv6Subnet     = 32
	MaxIPv6Subnet     = 64
	DefaultIPv6Subnet = 64
)

// Subnet reduces a derived address to the aggregate a rate limiter should key
// on: the /ipv6Prefix network for IPv6, the address unchanged for IPv4.
//
// IPv4 is deliberately never aggregated. Carrier-grade NAT already places many
// unrelated subscribers behind a single address — on Indian mobile networks
// especially — so widening beyond /32 would bucket strangers together and
// punish them for each other's traffic.
//
// The caller keeps the full address for identity and audit; this is only the
// bucket key.
func Subnet(addr string, ipv6Prefix int) string {
	parsed := net.ParseIP(addr)
	if parsed == nil {
		// Not an address we can reason about — pass it through rather than
		// inventing a key. Callers never hand us an empty string.
		return addr
	}
	if parsed.To4() != nil {
		return addr
	}
	return parsed.Mask(net.CIDRMask(ipv6Prefix, 128)).String()
}

// SubnetCIDR is Subnet in CIDR notation, for publication rather than for use as
// a bucket key.
//
// The prefix length is the point: bare, "2001:db8:1:1::" is indistinguishable
// from a client whose address genuinely is 2001:db8:1:1::, so a reader of an
// audit trail cannot tell an aggregate from a literal. "/64" says which it is,
// and any CIDR parser will take it.
func SubnetCIDR(addr string, ipv6Prefix int) string {
	parsed := net.ParseIP(addr)
	if parsed == nil {
		return addr
	}
	if parsed.To4() != nil {
		return addr + "/32"
	}
	return parsed.Mask(net.CIDRMask(ipv6Prefix, 128)).String() + "/" + strconv.Itoa(ipv6Prefix)
}
