package bgpls

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/internal/fuzzseed"
)

// FuzzUnmarshalBGPLSNLRI decodes a BGP-LS attribute (path attribute 29) and
// calls every getter, as the producer does for LS Node/Link/Prefix/SRv6 SID
// messages. Getters taking a protocol ID are called for each known protocol.
func FuzzUnmarshalBGPLSNLRI(f *testing.F) {
	fuzzseed.Quiet(f)
	for _, a := range fuzzseed.Attrs {
		if a[1] == 29 {
			f.Add(a[4:])
		}
	}
	protoType := reflect.TypeOf(base.ProtoID(0))
	f.Fuzz(func(t *testing.T, b []byte) {
		ls, err := UnmarshalBGPLSNLRI(b)
		if err != nil {
			return
		}
		v := reflect.ValueOf(ls)
		for i := 0; i < v.NumMethod(); i++ {
			m := v.Method(i)
			switch {
			case m.Type().NumIn() == 0:
				_, _ = json.Marshal(m.Call(nil)[0].Interface())
			case m.Type().NumIn() == 1 && m.Type().In(0) == protoType:
				for p := base.ProtoID(0); p <= base.SR+1; p++ {
					_, _ = json.Marshal(m.Call([]reflect.Value{reflect.ValueOf(p)})[0].Interface())
				}
			}
		}
		_, _ = json.Marshal(ls)
	})
}
