package multicast

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// UnmarshalMulticastNLRI builds MP NLRI object for multicast routes from the slice of bytes
func UnmarshalMulticastNLRI(b []byte, pathID bool) (*base.MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("MP Multicast NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	mpnlri := base.MPNLRI{}
	r, err := base.UnmarshalRoutes(b, pathID)
	if err != nil {
		return nil, err
	}
	mpnlri.NLRI = r

	return &mpnlri, nil
}

// UnmarshalMulticastNLRIWithState builds MP NLRI object for multicast routes
// (AFI 2 when ipv6, else 1; SAFI 2) from the slice of bytes, reading Path
// Identifiers as state s says (see base.UnmarshalRoutesWithState).
func UnmarshalMulticastNLRIWithState(b []byte, s base.PathIDState, ipv6 bool) (*base.MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("MP Multicast NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	return base.UnmarshalRoutesWithState(b, s, ipv6)
}
