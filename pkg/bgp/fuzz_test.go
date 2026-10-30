package bgp

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/internal/fuzzseed"
)

// FuzzUnmarshalBGPUpdate decodes a BGP UPDATE body and exercises the
// attribute getters that run on every Route Monitoring message.
func FuzzUnmarshalBGPUpdate(f *testing.F) {
	fuzzseed.Quiet(f)
	for _, u := range fuzzseed.UpdateBodies() {
		f.Add(u, true)
		f.Add(u, false)
	}
	f.Fuzz(func(t *testing.T, b []byte, as4 bool) {
		u, err := UnmarshalBGPUpdateWithAS4Hint(b, as4)
		if err != nil {
			return
		}
		_ = u.GetAllAttributeID()
		_, _ = u.GetNLRIType()
		_, _ = u.GetAttrPrefixSID()
		_, _ = u.GetBGPLSAttribute()
		_, _ = json.Marshal(u)
	})
}

// FuzzUnmarshalBGPOpenMessage decodes a BGP OPEN (without marker) and
// exercises the capability getters used when producing PeerUp messages.
func FuzzUnmarshalBGPOpenMessage(f *testing.F) {
	fuzzseed.Quiet(f)
	for _, o := range fuzzseed.OpenBodies() {
		f.Add(o)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := UnmarshalBGPOpenMessage(b)
		if err != nil {
			return
		}
		_, _ = o.Is4BytesASCapable()
		_ = o.AddPathCapability()
		_ = o.IsMultiLabelCapable()
		_, _ = o.BGPRoleCapability()
		_, _ = json.Marshal(o.GetCapabilities())
	})
}
