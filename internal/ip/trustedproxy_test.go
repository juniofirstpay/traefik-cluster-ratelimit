package ip

import (
	"net/http"
	"testing"
)

func req(remote, xff string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func strategy(t *testing.T, trusted ...string) *TrustedProxyStrategy {
	t.Helper()
	c, err := NewChecker(trusted)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	return &TrustedProxyStrategy{Checker: c}
}

func TestWalkResolve(t *testing.T) {
	s := strategy(t, "10.10.0.0/24", "10.10.1.0/24")

	cases := []struct {
		name       string
		remote     string
		xff        string
		wantIP     string
		wantSource Source
	}{
		{
			name:   "single entry from a trusted hop is the client",
			remote: "10.10.0.7:52000", xff: "203.0.113.9",
			wantIP: "203.0.113.9", wantSource: SourceXFF,
		},
		{
			// The position-independence claim: the same config is correct one
			// hop further in, where the chain has grown on the right.
			name:   "trusted hop appended on the right is skipped",
			remote: "10.10.0.7:52000", xff: "203.0.113.9, 10.10.1.4",
			wantIP: "203.0.113.9", wantSource: SourceXFF,
		},
		{
			// The spoofing case: the walk stops at the first untrusted entry
			// from the RIGHT, so prepended entries are never reached.
			name:   "prepended spoof is never reached",
			remote: "10.10.0.7:52000", xff: "1.2.3.4, 203.0.113.9",
			wantIP: "203.0.113.9", wantSource: SourceXFF,
		},
		{
			name:   "untrusted peer: forwarded headers are not read at all",
			remote: "198.51.100.20:41000", xff: "203.0.113.9",
			wantIP: "198.51.100.20", wantSource: SourcePeerUntrusted,
		},
		{
			name:   "trusted peer, no header",
			remote: "10.10.0.7:52000", xff: "",
			wantIP: "10.10.0.7", wantSource: SourcePeerNoXFF,
		},
		{
			name:   "every entry is ours",
			remote: "10.10.0.7:52000", xff: "10.10.0.3, 10.10.1.4",
			wantIP: "10.10.0.7", wantSource: SourcePeerAllTrusted,
		},
		{
			name:   "malformed entry stops the walk rather than being skipped",
			remote: "10.10.0.7:52000", xff: "203.0.113.9, unknown",
			wantIP: "10.10.0.7", wantSource: SourcePeerMalformed,
		},
		{
			name:   "RFC 7239 obfuscated identifier is rejected",
			remote: "10.10.0.7:52000", xff: "_hidden",
			wantIP: "10.10.0.7", wantSource: SourcePeerMalformed,
		},
		{
			name:   "port is stripped from an IPv4 entry",
			remote: "10.10.0.7:52000", xff: "203.0.113.9:51514",
			wantIP: "203.0.113.9", wantSource: SourceXFF,
		},
		{
			name:   "bracketed IPv6 with a port",
			remote: "10.10.0.7:52000", xff: "[2001:db8::1]:443",
			wantIP: "2001:db8::1", wantSource: SourceXFF,
		},
		{
			name:   "bare IPv6 is not mangled by the port strip",
			remote: "10.10.0.7:52000", xff: "2001:db8::1",
			wantIP: "2001:db8::1", wantSource: SourceXFF,
		},
		{
			name:   "IPv6 socket peer keeps its address",
			remote: "[2001:db8::99]:41000", xff: "",
			wantIP: "2001:db8::99", wantSource: SourcePeerUntrusted,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			gotIP, gotSource := s.Resolve(req(tc.remote, tc.xff))
			if gotIP != tc.wantIP || gotSource != tc.wantSource {
				t.Fatalf("got (%q, %q), want (%q, %q)", gotIP, gotSource, tc.wantIP, tc.wantSource)
			}
		})
	}
}

// TestWalkNeverReturnsEmpty is the guard against #5's defect class. An empty
// string is a valid map key, so returning one collapses every affected request
// into a single rate-limit bucket — silently.
func TestWalkNeverReturnsEmpty(t *testing.T) {
	s := strategy(t, "10.10.0.0/24")
	for _, xff := range []string{"", "   ", ",", ", ,", "unknown", "1.2.3.4, unknown", "not-an-ip"} {
		if got := s.GetIP(req("10.10.0.7:52000", xff)); got == "" {
			t.Fatalf("empty key for X-Forwarded-For %q", xff)
		}
	}
	if got := s.GetIP(req("garbage-without-a-port", "")); got == "" {
		t.Fatal("empty key for an unparseable RemoteAddr")
	}
}

// TestWalkCapsHeaderLength bounds the parse. A header this long is not a real
// proxy chain.
func TestWalkCapsHeaderLength(t *testing.T) {
	s := strategy(t, "10.10.0.0/24")
	long := "203.0.113.9"
	for i := 0; i < maxXFFEntries+5; i++ {
		long += ", 203.0.113.9"
	}
	gotIP, gotSource := s.Resolve(req("10.10.0.7:52000", long))
	if gotSource != SourcePeerMalformed || gotIP != "10.10.0.7" {
		t.Fatalf("over-long header: got (%q, %q), want the peer and %q", gotIP, gotSource, SourcePeerMalformed)
	}
}

// TestWalkWithNoCheckerIsSafe — a nil checker must not panic or trust headers.
func TestWalkWithNoCheckerIsSafe(t *testing.T) {
	s := &TrustedProxyStrategy{}
	gotIP, gotSource := s.Resolve(req("10.10.0.7:52000", "203.0.113.9"))
	if gotIP != "10.10.0.7" || gotSource != SourcePeerUntrusted {
		t.Fatalf("got (%q, %q), want the peer as untrusted", gotIP, gotSource)
	}
}
