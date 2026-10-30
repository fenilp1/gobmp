package base

// PathIDState says whether NLRI of an AFI/SAFI in a BMP Route Monitoring
// message carry the 4-octet ADD-PATH Path Identifier (RFC 7911 §3).
type PathIDState uint8

const (
	// PathIDUnknown means the state is not known: no Peer Up was seen for
	// the session.
	PathIDUnknown PathIDState = iota
	// PathIDAbsent means no NLRI carries a Path Identifier.
	PathIDAbsent
	// PathIDPresent means every NLRI carries a Path Identifier.
	PathIDPresent
	// PathIDExpectAbsent and PathIDExpectPresent give the setting that the
	// negotiated capabilities suggest for a RIB view whose encoding no RFC
	// fixes, such as post-policy Adj-RIB-In (RFC 7854 §4.2) or pre-policy
	// Adj-RIB-Out (RFC 8671 §5.2): a failed parse is retried with the other
	// setting.
	PathIDExpectAbsent
	PathIDExpectPresent
)

// Expected reports whether NLRI are expected to carry Path Identifiers.
func (s PathIDState) Expected() bool {
	return s == PathIDPresent || s == PathIDExpectPresent
}

// DecodeWithPathID calls parse with the Path Identifier setting of state s.
// A present or absent state is parsed once, so a malformed NLRI field is
// never turned into routes by reading it with the wrong setting (RFC 7606
// §5.3). Otherwise a failed parse is retried, once, with the setting flipped:
// the expected setting first, or guess when s is unknown. A result read with
// the setting opposite to an expected one has PathIDsFlipped set. The first
// error is returned.
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
		mp.PathIDsFlipped = s != PathIDUnknown
		return mp, nil
	}
	return nil, err
}
