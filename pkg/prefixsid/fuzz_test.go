package prefixsid

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/internal/fuzzseed"
)

// FuzzUnmarshalBGPAttrPrefixSID decodes a BGP Prefix-SID attribute value
// (RFC 8669, RFC 9252) and round-trips it through JSON.
func FuzzUnmarshalBGPAttrPrefixSID(f *testing.F) {
	fuzzseed.Quiet(f)
	for _, a := range fuzzseed.Attrs {
		if a[1] == 40 {
			f.Add(a[4:])
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		psid, err := UnmarshalBGPAttrPrefixSID(b)
		if err != nil {
			return
		}
		_ = psid.IsEmpty()
		_, _ = psid.Equal(psid)
		j, err := json.Marshal(psid)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		_ = json.Unmarshal(j, &PSid{})
	})
}
