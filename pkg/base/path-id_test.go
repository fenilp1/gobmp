package base

import (
	"errors"
	"reflect"
	"testing"
)

func TestDecodeWithPathID(t *testing.T) {
	tests := []struct {
		name  string
		s     PathIDState
		guess bool
		tried []bool
	}{
		{name: "present", s: PathIDPresent, tried: []bool{true}},
		{name: "absent", s: PathIDAbsent, guess: true, tried: []bool{false}},
		{name: "unknown", s: PathIDUnknown, tried: []bool{false, true}},
		{name: "unknown, guess set", s: PathIDUnknown, guess: true, tried: []bool{true, false}},
		{name: "expect absent", s: PathIDExpectAbsent, guess: true, tried: []bool{false, true}},
		{name: "expect present", s: PathIDExpectPresent, tried: []bool{true, false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tried []bool
			first := errors.New("first")
			_, err := DecodeWithPathID(tt.s, tt.guess, func(pathID bool) (*MPNLRI, error) {
				tried = append(tried, pathID)
				if len(tried) == 1 {
					return nil, first
				}
				return nil, errors.New("second")
			})
			if !reflect.DeepEqual(tried, tt.tried) || err != first {
				t.Errorf("tried %v, error %v; want %v and the first error", tried, err, tt.tried)
			}
		})
	}
}

// TestDecodeWithPathIDPlausible checks that the retry of an expected state
// keeps only a plausible result, while an unknown state, as used by the
// bool decoders, keeps any.
func TestDecodeWithPathIDPlausible(t *testing.T) {
	slash40 := []byte{0x28, 0x0a, 0x00, 0x00, 0x01, 0x00}                    // with Path IDs: 0x280a0000, 0.0.0.0/1
	trailing := []byte{0x00, 0x00, 0x00, 0x01, 0x18, 0x0a, 0x01, 0x02, 0x00} // without: /0 routes among others
	tests := []struct {
		name string
		b    []byte
		s    PathIDState
		ok   bool
	}{
		{name: "Path ID over 24 bits", b: slash40, s: PathIDExpectAbsent},
		{name: "Length 0 among routes", b: trailing, s: PathIDExpectPresent},
		{name: "Path ID over 24 bits, unknown", b: slash40, s: PathIDUnknown, ok: true},
		{name: "plausible retry", b: []byte{0x00, 0x00, 0x00, 0x07, 0x20, 0x0a, 0x00, 0x00, 0x01}, s: PathIDExpectAbsent, ok: true},
	}
	for _, tt := range tests {
		mp, err := UnmarshalRoutesWithState(tt.b, tt.s, false)
		if (err == nil) != tt.ok || (err == nil && !mp.PathIDsFlipped && tt.s != PathIDUnknown) {
			t.Errorf("%s: UnmarshalRoutesWithState() = %+v, %v, want a retried result %t", tt.name, mp, err, tt.ok)
		}
	}
}
