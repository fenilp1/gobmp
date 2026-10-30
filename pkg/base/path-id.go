package base

// PathIDState says whether NLRI of an AFI/SAFI carry the 4-octet ADD-PATH
// Path Identifier (RFC 7911 §3), and whether a parse that fails with that
// setting may be retried with the other one.
type PathIDState uint8

const (
	// PathIDUnknown means nothing is known, e.g. no Peer Up was seen for
	// the session: a failed parse is retried with the setting flipped.
	PathIDUnknown PathIDState = iota
	// PathIDAbsent means no NLRI carries a Path Identifier, and PathIDPresent
	// that every NLRI does. A failed parse is not retried, so these suit an
	// encoding that a protocol fixes, such as the BGP-LS IP Reachability
	// Information TLV (RFC 9552 §5.2.3.4), which has no Path Identifier.
	PathIDAbsent
	PathIDPresent
	// PathIDExpectAbsent and PathIDExpectPresent give the setting that the
	// negotiated ADD-PATH capabilities call for (RFC 7911 §5). A failed parse
	// is retried once with the other setting, for routers whose encoding of a
	// RIB view disagrees with the OPEN messages.
	PathIDExpectAbsent
	PathIDExpectPresent
)

// Expected reports whether NLRI are expected to carry Path Identifiers.
func (s PathIDState) Expected() bool {
	return s == PathIDPresent || s == PathIDExpectPresent
}

// DecodeWithPathID calls parse with the Path Identifier setting of state s.
// A present or absent state is parsed once. Otherwise a failed parse is
// retried, once, with the setting flipped: the expected setting first, or
// guess when s is unknown. A result read with the setting opposite to an
// expected one has PathIDsFlipped set, and is kept only if plausibleFlip
// accepts it. The first error is returned.
func DecodeWithPathID(s PathIDState, guess bool, parse func(pathID bool) (*MPNLRI, error)) (*MPNLRI, error) {
	switch s {
	case PathIDPresent:
		return parse(true)
	case PathIDAbsent:
		return parse(false)
	case PathIDExpectAbsent, PathIDExpectPresent:
		guess = s.Expected()
	}
	mp, err := parse(guess)
	if err == nil {
		return mp, nil
	}
	if mp, ferr := parse(!guess); ferr == nil {
		if s == PathIDUnknown {
			return mp, nil
		}
		if plausibleFlip(mp, !guess) {
			mp.PathIDsFlipped = true
			return mp, nil
		}
	}
	return nil, err
}

// plausibleFlip reports whether mp, read by the retry of an expected state
// with Path IDs (withPathIDs) or without, looks like routes rather than a
// malformed field: the retry turns many of those into routes. A Path ID
// over 0x00ffffff, from prefix octets taken as one, or a Length 0 route
// among others, from octets left over, rejects it. RFC 7911 §2 gives the
// identifier no semantics, so this only gates a retry that no RFC defines,
// never the parse with the expected setting.
func plausibleFlip(mp *MPNLRI, withPathIDs bool) bool {
	for _, r := range mp.NLRI {
		if withPathIDs && r.PathID > 0x00ffffff {
			return false
		}
		if !withPathIDs && r.Length == 0 && len(mp.NLRI) > 1 {
			return false
		}
	}
	return true
}
