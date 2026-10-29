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
