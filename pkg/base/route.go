package base

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// MPNLRI defines a collection of Prefixes/Routes sent in NLRI of MP_REACH or MP_UNREACH attribute
type MPNLRI struct {
	NLRI []Route
}

// Route defines a structure of NLRI prefix element
type Route struct {
	PathID uint32
	Length uint8
	// Used in Labeled Unicast and L3VPN NLRI
	Label []*Label
	// Used in Labeled L3VPN NLRI
	RD     *RD
	Prefix []byte
}

// UnmarshalRoutes decodes a sequence of RFC 4271 §4.3 prefixes, each
// preceded by a 4-octet ADD-PATH Path Identifier when pathID is set (RFC 7911
// §3). A failed parse is retried once with pathID flipped.
func UnmarshalRoutes(b []byte, pathID bool) ([]Route, error) {
	mp, err := decodeRoutes(b, PathIDUnknown, pathID)
	if err != nil {
		return nil, err
	}
	return mp.NLRI, nil
}

// UnmarshalRoutesWithState decodes a sequence of RFC 4271 §4.3 prefixes, as
// in the NLRI and Withdrawn Routes fields or SAFI 1 and 2 MP_REACH_NLRI and
// MP_UNREACH_NLRI, each preceded by a 4-octet ADD-PATH Path Identifier as
// state s says (RFC 7911 §3; see DecodeWithPathID).
func UnmarshalRoutesWithState(b []byte, s PathIDState) (*MPNLRI, error) {
	return decodeRoutes(b, s, false)
}

func decodeRoutes(b []byte, s PathIDState, guess bool) (*MPNLRI, error) {
	mp, err := DecodeWithPathID(s, guess, func(pathID bool) (*MPNLRI, error) {
		r, err := unmarshalRoutes(b, pathID)
		if err != nil {
			return nil, err
		}
		return &MPNLRI{NLRI: r}, nil
	})
	if err != nil {
		glog.Errorf("failed to reconstruct routes from slice %s with error: %+v", tools.MessageHex(b), err)
		return nil, err
	}
	return mp, nil
}

func unmarshalRoutes(b []byte, pathID bool) ([]Route, error) {
	if glog.V(6) {
		glog.Infof("Routes Raw: %s Path ID flag: %t", tools.MessageHex(b), pathID)
	}
	// Handle EoR case.
	routes := make([]Route, 0, len(b)/4)
	for p := 0; p < len(b); {
		route := Route{}
		// Check if there is Path ID in NLRI
		if pathID {
			if p+4 > len(b) {
				return nil, fmt.Errorf("not enough bytes to reconstruct routes")
			}
			route.PathID = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
			if p >= len(b) {
				return nil, fmt.Errorf("not enough bytes to reconstruct routes")
			}
		}
		// Updating length
		route.Length = b[p]
		l := route.Length / 8
		if route.Length%8 != 0 {
			l++
		}
		p++
		// The sum of a current pointer in the slice and safeOffset should not exceed the byte slice length.
		if p+int(l) > len(b) {
			return nil, fmt.Errorf("not enough bytes to reconstruct route")
		}
		route.Prefix = make([]byte, l)
		copy(route.Prefix, b[p:p+int(l)])
		p += int(l)
		routes = append(routes, route)
	}

	return routes, nil
}
