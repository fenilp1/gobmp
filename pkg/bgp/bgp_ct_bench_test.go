package bgp

import "testing"

// BenchmarkGetNLRICT decodes an IPv4 BGP Classful Transport MP_REACH_NLRI
// (RFC 9832 §6.1) carrying two labeled RD:prefix NLRIs.
func BenchmarkGetNLRICT(b *testing.B) {
	attr := ctMPReach(1, []byte{192, 0, 2, 1}, ctV4NLRI)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		mp, err := UnmarshalMPReachNLRI(attr, false)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := mp.GetNLRICT(); err != nil {
			b.Fatal(err)
		}
	}
}
