package ip

import (
	"net"
	"net/http"
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
