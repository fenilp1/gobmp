package base

import (
	"errors"
	"reflect"
	"testing"
)

func TestReadLabelField(t *testing.T) {
	// Labels 100 (S=0) and 200 (S=1), then one more byte.
	b := []byte{0x00, 0x06, 0x40, 0x00, 0x0c, 0x81, 0xff}
	tests := []struct {
		name   string
		b      []byte
		f      LabelField
		values []uint32 // nil: no labels
		n      int
		fail   bool
	}{
		{name: "stack ends at S=1", b: b, f: LabelStack, values: []uint32{100, 200}, n: 6},
		{name: "single label ignores S", b: b, f: SingleLabel, values: []uint32{100}, n: 3},
		{name: "SRv6 reads one field", b: b, f: SRv6Label, values: []uint32{0x640}, n: 3},
		{name: "compatibility field skipped", b: b, f: CompatibilityField, n: 3},
		{name: "stack without S=1", b: b[:3], f: LabelStack, fail: true},
		{name: "short label", b: b[:2], f: SingleLabel, fail: true},
		{name: "short compatibility field", b: b[:2], f: CompatibilityField, fail: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels, n, err := ReadLabelField(tt.b, tt.f)
			if tt.fail {
				if err == nil {
					t.Fatalf("ReadLabelField() = %v, %d, want an error", labels, n)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadLabelField() error: %v", err)
			}
			var values []uint32
			for _, l := range labels {
				values = append(values, l.Value)
			}
			if !reflect.DeepEqual(values, tt.values) || n != tt.n {
				t.Errorf("ReadLabelField() = %v, %d, want %v, %d", values, n, tt.values, tt.n)
			}
		})
	}
}

func TestDecodeLabeledNLRIOrder(t *testing.T) {
	tests := []struct {
		name  string
		m     MultiLabel
		valid map[LabelField]bool
		tried []LabelField
		want  LabelField
		fail  bool
	}{
		{name: "confirmed", m: MultiLabelConfirmed, valid: map[LabelField]bool{LabelStack: true, SingleLabel: true}, tried: []LabelField{LabelStack}, want: LabelStack},
		{name: "confirmed, stack invalid", m: MultiLabelConfirmed, valid: map[LabelField]bool{SingleLabel: true}, tried: []LabelField{LabelStack}, fail: true},
		{name: "absent", m: MultiLabelAbsent, valid: map[LabelField]bool{LabelStack: true, SingleLabel: true}, tried: []LabelField{SingleLabel}, want: SingleLabel},
		{name: "absent, single invalid", m: MultiLabelAbsent, valid: map[LabelField]bool{LabelStack: true}, tried: []LabelField{SingleLabel, LabelStack}, want: LabelStack},
		{name: "unknown", m: MultiLabelUnknown, valid: map[LabelField]bool{LabelStack: true, SingleLabel: true}, tried: []LabelField{LabelStack}, want: LabelStack},
		{name: "unknown, stack invalid", m: MultiLabelUnknown, valid: map[LabelField]bool{SingleLabel: true}, tried: []LabelField{LabelStack, SingleLabel}, want: SingleLabel},
		{name: "unknown, both invalid", m: MultiLabelUnknown, tried: []LabelField{LabelStack, SingleLabel}, fail: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tried []LabelField
			first := errors.New("first")
			mp, err := DecodeLabeledNLRI(tt.m, func(f LabelField) (*MPNLRI, error) {
				tried = append(tried, f)
				if !tt.valid[f] {
					if len(tried) == 1 {
						return nil, first
					}
					return nil, errors.New("second")
				}
				return &MPNLRI{NLRI: []Route{{Length: uint8(f)}}}, nil
			})
			if !reflect.DeepEqual(tried, tt.tried) {
				t.Errorf("tried %v, want %v", tried, tt.tried)
			}
			if tt.fail {
				if err != first {
					t.Errorf("error = %v, want the first error", err)
				}
				return
			}
			if err != nil || LabelField(mp.NLRI[0].Length) != tt.want {
				t.Errorf("DecodeLabeledNLRI() = %+v, %v, want reading %d", mp, err, tt.want)
			}
		})
	}
}
