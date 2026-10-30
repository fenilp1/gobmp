package unicast

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

func luNLRI(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// TestLUNLRIRFC8277Conformance checks UnmarshalLUNLRI against the RFC 8277 §2
// NLRI encodings for AFI 1/2 SAFI 4, with the Multiple Labels Capability
// confirmed, absent and unknown.
func TestLUNLRIRFC8277Conformance(t *testing.T) {
	v4Host := []byte{0x0a, 0x00, 0x00, 0x01}                        // 10.0.0.1
	v6Net := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00} // 2001:db8:1::/64
	// fd00:1234:5678:9abc::/64, no 3 bytes of which read as a label with S=1.
	v6Alt := []byte{0xfd, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}
	pathID := []byte{0x00, 0x00, 0x00, 0x07}
	twoLabels := []byte{0x00, 0x06, 0x40, 0x00, 0x0c, 0x81} // 100 (S=0), 200 (S=1)
	// Length 32, label 1000 (S=1), 48.0.0.0/8, then an NLRI of Length 0.
	zeroLength := []byte{0x20, 0x00, 0x3e, 0x81, 0x30, 0x00, 0x3e, 0x81, 0x0a, 0x00, 0x00}
	tests := []struct {
		name   string
		opts   Options
		nlri   []byte
		fail   bool
		labels []uint32 // nil: no labels
		prefix []byte
		length uint8
		pathID uint32
	}{
		// RFC 8277 §2.4: the Compatibility field MUST be ignored on reception.
		{name: "v4 withdraw compatibility 0x000640", opts: Options{Withdraw: true}, nlri: luNLRI([]byte{0x38, 0x00, 0x06, 0x40}, v4Host), prefix: v4Host, length: 32},
		{name: "v4 withdraw compatibility 0x000000", opts: Options{Withdraw: true}, nlri: luNLRI([]byte{0x30, 0x00, 0x00, 0x00}, v4Host[:3]), prefix: v4Host[:3], length: 24},
		{name: "v4 withdraw compatibility 0x800000", opts: Options{Withdraw: true}, nlri: luNLRI([]byte{0x38, 0x80, 0x00, 0x00}, v4Host), prefix: v4Host, length: 32},
		{name: "v4 withdraw compatibility 0x000640, confirmed", opts: Options{Withdraw: true, MultiLabel: base.MultiLabelConfirmed}, nlri: luNLRI([]byte{0x38, 0x00, 0x06, 0x40}, v4Host), prefix: v4Host, length: 32},
		{name: "v6 withdraw compatibility 0x000640", opts: Options{Withdraw: true, AFI: 2}, nlri: luNLRI([]byte{0x58, 0x00, 0x06, 0x40}, v6Net), prefix: v6Net, length: 64},
		{name: "v6 withdraw compatibility 0xffffff", opts: Options{Withdraw: true, AFI: 2}, nlri: luNLRI([]byte{0x58, 0xff, 0xff, 0xff}, v6Net), prefix: v6Net, length: 64},

		// RFC 8277 §2.2: on an announcement 0x800000 is label 524288.
		{name: "v4 first label 0x800000, absent", opts: Options{MultiLabel: base.MultiLabelAbsent}, nlri: luNLRI([]byte{0x38, 0x80, 0x00, 0x00}, v4Host), labels: []uint32{0x80000}, prefix: v4Host, length: 32},
		{name: "v4 first label 0x800000, unknown", nlri: luNLRI([]byte{0x38, 0x80, 0x00, 0x00}, v4Host), labels: []uint32{0x80000}, prefix: v4Host, length: 32},
		{name: "v4 first label 0x800000, confirmed", opts: Options{MultiLabel: base.MultiLabelConfirmed}, nlri: luNLRI([]byte{0x38, 0x80, 0x00, 0x00}, v4Host), fail: true},
		{name: "v4 labels 0x800000 and 200, confirmed", opts: Options{MultiLabel: base.MultiLabelConfirmed}, nlri: luNLRI([]byte{0x50, 0x80, 0x00, 0x00, 0x00, 0x0c, 0x81}, v4Host), labels: []uint32{0x80000, 200}, prefix: v4Host, length: 32},
		{name: "v6 first label 0x800000, absent", opts: Options{MultiLabel: base.MultiLabelAbsent, AFI: 2}, nlri: luNLRI([]byte{0x58, 0x80, 0x00, 0x00}, v6Net), labels: []uint32{0x80000}, prefix: v6Net, length: 64},
		{name: "v6 first label 0x800000, unknown", opts: Options{AFI: 2}, nlri: luNLRI([]byte{0x58, 0x80, 0x00, 0x00}, v6Alt), labels: []uint32{0x80000}, prefix: v6Alt, length: 64},
		{name: "v4 label 0x000000, absent", opts: Options{MultiLabel: base.MultiLabelAbsent}, nlri: luNLRI([]byte{0x38, 0x00, 0x00, 0x00}, v4Host), labels: []uint32{0}, prefix: v4Host, length: 32},

		// RFC 8277 §2.2: without the capability the S bit MUST be ignored.
		{name: "v4 one label S=0, absent", opts: Options{MultiLabel: base.MultiLabelAbsent}, nlri: luNLRI([]byte{0x38, 0x00, 0x3e, 0x80}, v4Host), labels: []uint32{1000}, prefix: v4Host, length: 32},
		{name: "v4 one label S=0, unknown", nlri: luNLRI([]byte{0x38, 0x00, 0x3e, 0x80}, v4Host), labels: []uint32{1000}, prefix: v4Host, length: 32},
		{name: "v6 one label S=0, absent", opts: Options{MultiLabel: base.MultiLabelAbsent, AFI: 2}, nlri: luNLRI([]byte{0x58, 0x00, 0x3e, 0x80}, v6Net), labels: []uint32{1000}, prefix: v6Net, length: 64},
		{name: "v6 one label S=0, unknown", opts: Options{AFI: 2}, nlri: luNLRI([]byte{0x58, 0x00, 0x3e, 0x80}, v6Alt), labels: []uint32{1000}, prefix: v6Alt, length: 64},
		// RFC 8277 §2.3: the stack ends at the label with S=1.
		{name: "v4 one label S=0, confirmed", opts: Options{MultiLabel: base.MultiLabelConfirmed}, nlri: luNLRI([]byte{0x38, 0x00, 0x3e, 0x80}, v4Host), fail: true},

		// Two labels.
		{name: "v4 two labels, confirmed", opts: Options{MultiLabel: base.MultiLabelConfirmed}, nlri: luNLRI([]byte{0x50}, twoLabels, v4Host), labels: []uint32{100, 200}, prefix: v4Host, length: 32},
		{name: "v4 two labels, unknown", nlri: luNLRI([]byte{0x50}, twoLabels, v4Host), labels: []uint32{100, 200}, prefix: v4Host, length: 32},
		// One label would leave a 56-bit IPv4 prefix.
		{name: "v4 two labels, absent", opts: Options{MultiLabel: base.MultiLabelAbsent}, nlri: luNLRI([]byte{0x50}, twoLabels, v4Host), labels: []uint32{100, 200}, prefix: v4Host, length: 32},
		{name: "v6 two labels, confirmed", opts: Options{MultiLabel: base.MultiLabelConfirmed, AFI: 2}, nlri: luNLRI([]byte{0x70}, twoLabels, v6Net), labels: []uint32{100, 200}, prefix: v6Net, length: 64},
		{name: "v6 two labels, unknown", opts: Options{AFI: 2}, nlri: luNLRI([]byte{0x70}, twoLabels, v6Net), labels: []uint32{100, 200}, prefix: v6Net, length: 64},
		// RFC 8277 §2.1, §2.2: a sender without the capability MUST NOT
		// bind two labels; one label leaves a valid 88-bit IPv6 prefix.
		{name: "v6 two labels, absent", opts: Options{MultiLabel: base.MultiLabelAbsent, AFI: 2}, nlri: luNLRI([]byte{0x70}, twoLabels, v6Net), labels: []uint32{100}, prefix: luNLRI(twoLabels[3:], v6Net), length: 88},
		{name: "v4 three labels, confirmed", opts: Options{MultiLabel: base.MultiLabelConfirmed}, nlri: luNLRI([]byte{0x68, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x80, 0x00, 0x12, 0xc1}, v4Host), labels: []uint32{100, 200, 300}, prefix: v4Host, length: 32},

		// Prefix bytes that read as a label with S=1 (the LU form of the
		// label-like RD ambiguity): label 1000 (S=0), 10.0.1.1/32.
		{name: "v4 label-like prefix, absent", opts: Options{MultiLabel: base.MultiLabelAbsent}, nlri: luNLRI([]byte{0x38, 0x00, 0x3e, 0x80, 0x0a, 0x00, 0x01, 0x01}), labels: []uint32{1000}, prefix: []byte{0x0a, 0x00, 0x01, 0x01}, length: 32},
		// Unknown: the S bit walk goes first and is valid, labels 1000 and
		// 40960 with 1.0.0.0/8.
		{name: "v4 label-like prefix, unknown", nlri: luNLRI([]byte{0x38, 0x00, 0x3e, 0x80, 0x0a, 0x00, 0x01, 0x01}), labels: []uint32{1000, 40960}, prefix: []byte{0x01}, length: 8},
		// Unknown: 2001:db8:1::/64 after an S=0 label reads as label 131088
		// with S=1 and b800:100::/40.
		{name: "v6 label-like prefix, unknown", opts: Options{AFI: 2}, nlri: luNLRI([]byte{0x58, 0x00, 0x3e, 0x80}, v6Net), labels: []uint32{1000, 131088}, prefix: []byte{0xb8, 0x00, 0x01, 0x00, 0x00}, length: 40},
		{name: "v6 label-like prefix, absent", opts: Options{MultiLabel: base.MultiLabelAbsent, AFI: 2}, nlri: luNLRI([]byte{0x38, 0x00, 0x3e, 0x80, 0x20, 0x01, 0x0d, 0xb8}), labels: []uint32{1000}, prefix: []byte{0x20, 0x01, 0x0d, 0xb8}, length: 32},

		// RFC 8277 §2.2, RFC 7606 §5.3: at most 32 prefix bits for AFI 1
		// and 128 for AFI 2.
		{name: "v4 prefix of 40 bits, absent", opts: Options{MultiLabel: base.MultiLabelAbsent}, nlri: luNLRI([]byte{0x40, 0x00, 0x06, 0x41}, v4Host, []byte{0x00}), fail: true},
		{name: "v4 prefix of 33 bits, unknown", nlri: luNLRI([]byte{0x39, 0x00, 0x06, 0x41}, v4Host, []byte{0x00}), fail: true},
		{name: "v4 withdraw prefix of 40 bits", opts: Options{Withdraw: true}, nlri: luNLRI([]byte{0x40, 0x80, 0x00, 0x00}, v4Host, []byte{0x00}), fail: true},
		{name: "v4 prefix of 32 bits", opts: Options{MultiLabel: base.MultiLabelAbsent}, nlri: luNLRI([]byte{0x38, 0x00, 0x06, 0x41}, v4Host), labels: []uint32{100}, prefix: v4Host, length: 32},
		{name: "v6 prefix of 136 bits", opts: Options{MultiLabel: base.MultiLabelAbsent, AFI: 2}, nlri: luNLRI([]byte{0xa0, 0x00, 0x06, 0x41}, v6Net, v6Net, []byte{0x00}), fail: true},
		{name: "v6 prefix of 128 bits", opts: Options{MultiLabel: base.MultiLabelAbsent, AFI: 2}, nlri: luNLRI([]byte{0x98, 0x00, 0x06, 0x41}, v6Net, v6Net), labels: []uint32{100}, prefix: luNLRI(v6Net, v6Net), length: 128},
		{name: "length shorter than the label", opts: Options{MultiLabel: base.MultiLabelAbsent}, nlri: []byte{0x10, 0x00, 0x06, 0x41}, fail: true},

		// ADD-PATH (RFC 8277 §2.2, §2.3; RFC 7911 §3).
		{name: "v4 ADD-PATH first label 0x800000", opts: Options{PathID: true, MultiLabel: base.MultiLabelAbsent}, nlri: luNLRI(pathID, []byte{0x38, 0x80, 0x00, 0x00}, v4Host), labels: []uint32{0x80000}, prefix: v4Host, length: 32, pathID: 7},
		{name: "v4 ADD-PATH one label S=0", opts: Options{PathID: true, MultiLabel: base.MultiLabelAbsent}, nlri: luNLRI(pathID, []byte{0x38, 0x00, 0x3e, 0x80}, v4Host), labels: []uint32{1000}, prefix: v4Host, length: 32, pathID: 7},
		{name: "v4 ADD-PATH two labels, confirmed", opts: Options{PathID: true, MultiLabel: base.MultiLabelConfirmed}, nlri: luNLRI(pathID, []byte{0x50}, twoLabels, v4Host), labels: []uint32{100, 200}, prefix: v4Host, length: 32, pathID: 7},
		{name: "v4 ADD-PATH withdraw compatibility 0x000640", opts: Options{PathID: true, Withdraw: true}, nlri: luNLRI(pathID, []byte{0x38, 0x00, 0x06, 0x40}, v4Host), prefix: v4Host, length: 32, pathID: 7},
		{name: "v4 ADD-PATH prefix of 40 bits", opts: Options{PathID: true, MultiLabel: base.MultiLabelAbsent}, nlri: luNLRI(pathID, []byte{0x40, 0x00, 0x06, 0x41}, v4Host, []byte{0x00}), fail: true},
		{name: "v6 ADD-PATH first label 0x800000", opts: Options{PathID: true, MultiLabel: base.MultiLabelAbsent, AFI: 2}, nlri: luNLRI(pathID, []byte{0x58, 0x80, 0x00, 0x00}, v6Net), labels: []uint32{0x80000}, prefix: v6Net, length: 64, pathID: 7},
		{name: "v6 ADD-PATH withdraw compatibility 0x000640", opts: Options{PathID: true, Withdraw: true, AFI: 2}, nlri: luNLRI(pathID, []byte{0x58, 0x00, 0x06, 0x40}, v6Net), prefix: v6Net, length: 64, pathID: 7},
		// Path IDs absent with the flag set: one retry without. Present with
		// it unset: no retry, as many malformed fields read as a route once
		// their first four octets are taken as a Path ID.
		{name: "v4 Path ID with flag unset", opts: Options{MultiLabel: base.MultiLabelAbsent}, nlri: luNLRI(pathID, []byte{0x38, 0x00, 0x06, 0x41}, v4Host), fail: true},
		{name: "v6 Path ID with flag unset", opts: Options{AFI: 2}, nlri: luNLRI(pathID, []byte{0x58, 0x00, 0x06, 0x41}, v6Net), fail: true},
		{name: "v4 no Path ID with flag set", opts: Options{PathID: true, MultiLabel: base.MultiLabelAbsent}, nlri: luNLRI([]byte{0x38, 0x00, 0x06, 0x41}, v4Host), labels: []uint32{100}, prefix: v4Host, length: 32},
		// Malformed fields that read as one route only with Path IDs: the
		// second NLRI has Length 0, would be Path ID 0x20003e81.
		{name: "zero Length, flag unset", nlri: zeroLength, fail: true},
		{name: "v4 label 396336 S=0, flag unset", nlri: []byte{0x30, 0x20, 0x56, 0x71, 0x27, 0x60, 0xc3, 0x00, 0x00, 0x00}, fail: true},
		{name: "v6 Length 88 field of 9 octets, flag unset", opts: Options{AFI: 2}, nlri: []byte{0x58, 0xe1, 0xc1, 0x61, 0x20, 0x01, 0x0d, 0xb8, 0x6b}, fail: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := tt.opts
			if opts.AFI == 0 {
				opts.AFI = 1
			}
			got, err := UnmarshalLUNLRIWithOptions(tt.nlri, opts)
			if tt.fail {
				if err == nil {
					t.Fatalf("decoded %+v, want an error", got.NLRI)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalLUNLRIWithOptions() error: %v", err)
			}
			if len(got.NLRI) != 1 {
				t.Fatalf("decoded %d routes, want 1", len(got.NLRI))
			}
			r := got.NLRI[0]
			var labels []uint32
			for _, l := range r.Label {
				labels = append(labels, l.Value)
			}
			if !reflect.DeepEqual(labels, tt.labels) {
				t.Errorf("labels = %v, want %v", labels, tt.labels)
			}
			if !bytes.Equal(r.Prefix, tt.prefix) || r.Length != tt.length || r.PathID != tt.pathID {
				t.Errorf("route = %x/%d path %d, want %x/%d path %d", r.Prefix, r.Length, r.PathID, tt.prefix, tt.length, tt.pathID)
			}
		})
	}
}

// TestLUNLRIMultipleRoutesRFC8277 checks that the label reading is chosen for
// the whole NLRI field: with the capability absent, one label each.
func TestLUNLRIMultipleRoutesRFC8277(t *testing.T) {
	nlri := luNLRI(
		[]byte{0x38, 0x00, 0x3e, 0x80, 0x0a, 0x00, 0x00, 0x01}, // 1000 (S=0), 10.0.0.1/32
		[]byte{0x38, 0x80, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02}, // 524288 (S=0), 10.0.0.2/32
		[]byte{0x30, 0x00, 0x06, 0x41, 0x0a, 0x00, 0x03},       // 100 (S=1), 10.0.3.0/24
	)
	got, err := UnmarshalLUNLRIWithOptions(nlri, Options{MultiLabel: base.MultiLabelAbsent, AFI: 1})
	if err != nil {
		t.Fatalf("UnmarshalLUNLRIWithOptions() error: %v", err)
	}
	want := []uint32{1000, 0x80000, 100}
	if len(got.NLRI) != len(want) {
		t.Fatalf("decoded %d routes, want %d", len(got.NLRI), len(want))
	}
	for i, r := range got.NLRI {
		if len(r.Label) != 1 || r.Label[0].Value != want[i] {
			t.Errorf("route %d labels = %v, want [%d]", i, r.Label, want[i])
		}
	}
}
