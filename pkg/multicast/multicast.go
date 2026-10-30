package multicast

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// UnmarshalMulticastNLRI builds MP NLRI object for multicast routes (AFI 1/2
// SAFI 2) from the slice of bytes, with the ADD-PATH state s (see
// base.UnmarshalRoutes).
func UnmarshalMulticastNLRI(b []byte, s base.PathIDState) (*base.MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("MP Multicast NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	mpnlri := base.MPNLRI{}
	r, err := base.UnmarshalRoutes(b, s)
	if err != nil {
		return nil, err
	}
	mpnlri.NLRI = r

	return &mpnlri, nil
}
