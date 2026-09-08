package ip

import "testing"

func TestSubnetAggregation(t *testing.T) {
	cases := []struct {
		name   string
		addr   string
		prefix int
		want   string
	}{
		{"IPv4 is never aggregated", "203.0.113.9", 64, "203.0.113.9"},
		{"IPv4 unaffected by the prefix", "203.0.113.9", 32, "203.0.113.9"},
		{"IPv6 masked to /64", "2001:db8:1:1::1", 64, "2001:db8:1:1::"},
		{"IPv6 same /64, different host bits", "2001:db8:1:1::dead:beef", 64, "2001:db8:1:1::"},
		{"IPv6 different /64", "2001:db8:1:2::1", 64, "2001:db8:1:2::"},
		{"IPv6 widened to /56", "2001:db8:1:1::1", 56, "2001:db8:1::"},
		{"IPv6 widened to /48", "2001:db8:1:1::1", 48, "2001:db8:1::"},
		{"unparseable passes through", "not-an-ip", 64, "not-an-ip"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := Subnet(tc.addr, tc.prefix); got != tc.want {
				t.Fatalf("Subnet(%q, %d) = %q, want %q", tc.addr, tc.prefix, got, tc.want)
			}
		})
	}
}

// TestPrivacyExtensionRotationCollapses is the point of the whole change: a
// client rotating its low 64 bits, which is default OS behaviour rather than
// an attack, must land in ONE bucket.
func TestPrivacyExtensionRotationCollapses(t *testing.T) {
	rotations := []string{
		"2001:db8:cafe:1::1",
		"2001:db8:cafe:1:f8a2:9c31:0e77:4b21",
		"2001:db8:cafe:1:2d4e:88ff:fe0a:1234",
		"2001:db8:cafe:1::ffff",
	}
	first := Subnet(rotations[0], 64)
	for _, r := range rotations[1:] {
		if got := Subnet(r, 64); got != first {
			t.Fatalf("rotation %q produced a new bucket %q, want %q", r, got, first)
		}
	}
	// ...and a genuinely different network still gets its own.
	if Subnet("2001:db8:cafe:2::1", 64) == first {
		t.Fatal("a different /64 collapsed into the same bucket")
	}
}
