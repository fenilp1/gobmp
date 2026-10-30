package bgp

import (
	"encoding/binary"
	"reflect"
	"testing"
)

// pathAttr encodes a path attribute with a one-octet length.
func pathAttr(typ byte, value []byte) []byte {
	return append([]byte{0xC0, typ, byte(len(value))}, value...)
}

// pathAttrExt encodes a path attribute with a two-octet length.
func pathAttrExt(typ byte, value []byte) []byte {
	b := binary.BigEndian.AppendUint16([]byte{0xD0, typ}, uint16(len(value)))
	return append(b, value...)
}

// seg2 and seg4 encode an AS_PATH segment with 2- and 4-octet AS numbers.
func seg2(typ byte, asns ...uint16) []byte {
	b := []byte{typ, byte(len(asns))}
	for _, as := range asns {
		b = binary.BigEndian.AppendUint16(b, as)
	}
	return b
}

func seg4(typ byte, asns ...uint32) []byte {
	b := []byte{typ, byte(len(asns))}
	for _, as := range asns {
		b = binary.BigEndian.AppendUint32(b, as)
	}
	return b
}

func concat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// asnRange returns n AS numbers counting up from first.
func asnRange(first uint32, n int) []uint32 {
	asns := make([]uint32, n)
	for i := range asns {
		asns[i] = first + uint32(i)
	}
	return asns
}

func asns16(asns []uint32) []uint16 {
	b := make([]uint16, len(asns))
	for i, as := range asns {
		b[i] = uint16(as)
	}
	return b
}

func seq(asns ...uint32) ASPathSegment { return ASPathSegment{Type: asSequence, ASNs: asns} }
func set(asns ...uint32) ASPathSegment { return ASPathSegment{Type: asSet, ASNs: asns} }
func confedSeq(asns ...uint32) ASPathSegment {
	return ASPathSegment{Type: asConfedSequence, ASNs: asns}
}

type asPathResult struct {
	segments      []ASPathSegment
	asPath        []uint32
	asPathCount   int32
	originAS      uint32
	as4Path       []uint32
	as4PathCount  int32
	as4Aggregator []byte
}

const testOwnAS = 64512

func decodeASPathResult(t *testing.T, attrs []byte, as4 *bool) asPathResult {
	t.Helper()
	_, ba, err := unmarshalBGPPathAttributes(attrs, as4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return asPathResult{
		segments:      ba.ASPathSegments,
		asPath:        ba.ASPath,
		asPathCount:   ba.ASPathCount,
		originAS:      ba.OriginAS(testOwnAS),
		as4Path:       ba.AS4Path,
		as4PathCount:  ba.AS4PathCount,
		as4Aggregator: ba.AS4Aggregator,
	}
}

func TestUnmarshalBaseAttributes_RFC6793ASPath(t *testing.T) {
	as2 := false
	as4 := true
	as4Aggregator := []byte{0, 1, 0x11, 0x70, 10, 0, 0, 1} // AS 70000
	long := asnRange(1000, 255)
	tests := []struct {
		name  string
		as4   *bool
		attrs []byte
		want  asPathResult
	}{
		{
			name: "2-octet session: AS_TRANS replaced from AS4_PATH",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, seg2(asSequence, 65001, 3356, ASTrans)),
				pathAttr(17, seg4(asSequence, 3356, 4200000001)),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(65001, 3356, 4200000001)},
				asPath:       []uint32{65001, 3356, 4200000001},
				asPathCount:  3,
				originAS:     4200000001,
				as4Path:      []uint32{3356, 4200000001},
				as4PathCount: 2,
			},
		},
		{
			// No hint is passed only by the exported no-hint APIs such as
			// UnmarshalBGPBaseAttributes; this AS_PATH parses only at 2 octets.
			name: "no hint: 2-octet width detected, merged",
			attrs: concat(
				pathAttr(2, seg2(asSequence, 100, ASTrans)),
				pathAttr(17, seg4(asSequence, 70000)),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(100, 70000)},
				asPath:       []uint32{100, 70000},
				asPathCount:  2,
				originAS:     70000,
				as4Path:      []uint32{70000},
				as4PathCount: 1,
			},
		},
		{
			name: "equal counts: AS4_PATH is the whole path",
			as4:  &as2,
			attrs: concat(
				pathAttr(17, seg4(asSequence, 70000)),
				pathAttr(2, seg2(asSequence, ASTrans)),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(70000)},
				asPath:       []uint32{70000},
				asPathCount:  1,
				originAS:     70000,
				as4Path:      []uint32{70000},
				as4PathCount: 1,
			},
		},
		{
			name: "AS4_PATH segments split on the wire are joined",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, seg2(asSequence, 100, ASTrans, ASTrans)),
				pathAttr(17, concat(seg4(asSequence, 70000), seg4(asSequence, 80000))),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(100, 70000, 80000)},
				asPath:       []uint32{100, 70000, 80000},
				asPathCount:  3,
				originAS:     80000,
				as4Path:      []uint32{70000, 80000},
				as4PathCount: 2,
			},
		},
		{
			name: "joined segment fills 255 AS numbers",
			as4:  &as2,
			attrs: concat(
				pathAttrExt(2, seg2(asSequence, append(asns16(long[:250]), ASTrans, ASTrans, ASTrans, ASTrans, ASTrans)...)),
				pathAttr(17, seg4(asSequence, asnRange(70000, 5)...)),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(append(long[:250:250], asnRange(70000, 5)...)...)},
				asPath:       append(long[:250:250], asnRange(70000, 5)...),
				asPathCount:  255,
				originAS:     70004,
				as4Path:      asnRange(70000, 5),
				as4PathCount: 5,
			},
		},
		{
			// RFC 4271 Section 5.1.2: a segment holds at most 255 AS numbers.
			name: "segments not joined past 255 AS numbers",
			as4:  &as2,
			attrs: concat(
				pathAttrExt(2, concat(seg2(asSequence, asns16(long)...), seg2(asSequence, 100, ASTrans))),
				pathAttr(17, seg4(asSequence, 70000)),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(long...), seq(100, 70000)},
				asPath:       append(long[:255:255], 100, 70000),
				asPathCount:  257,
				originAS:     70000,
				as4Path:      []uint32{70000},
				as4PathCount: 1,
			},
		},
		{
			name: "leading confed segment is kept",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, concat(seg2(asConfedSequence, 65001), seg2(asSequence, 100, ASTrans))),
				pathAttr(17, seg4(asSequence, 70000)),
			),
			want: asPathResult{
				segments:     []ASPathSegment{confedSeq(65001), seq(100, 70000)},
				asPath:       []uint32{65001, 100, 70000},
				asPathCount:  3,
				originAS:     70000,
				as4Path:      []uint32{70000},
				as4PathCount: 1,
			},
		},
		{
			name: "confed segment adjacent to a prepended segment is kept",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, concat(seg2(asSequence, 100), seg2(asConfedSequence, 65001), seg2(asSequence, ASTrans))),
				pathAttr(17, seg4(asSequence, 70000)),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(100), confedSeq(65001), seq(70000)},
				asPath:       []uint32{100, 65001, 70000},
				asPathCount:  3,
				originAS:     70000,
				as4Path:      []uint32{70000},
				as4PathCount: 1,
			},
		},
		{
			name: "AS_SET counts as one and is not joined",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, concat(seg2(asSequence, 100, 200), seg2(asSet, ASTrans, 300))),
				pathAttr(17, seg4(asSet, 70000, 300)),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(100, 200), set(70000, 300)},
				asPath:       []uint32{100, 200, 70000, 300},
				asPathCount:  4,
				originAS:     0,
				as4Path:      []uint32{70000, 300},
				as4PathCount: 2,
			},
		},
		{
			name: "AGGREGATOR is AS_TRANS: merged",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, seg2(asSequence, 100, ASTrans)),
				pathAttr(7, []byte{0x5B, 0xA0, 10, 0, 0, 1}),
				pathAttr(17, seg4(asSequence, 70000)),
				pathAttr(18, as4Aggregator),
			),
			want: asPathResult{
				segments:      []ASPathSegment{seq(100, 70000)},
				asPath:        []uint32{100, 70000},
				asPathCount:   2,
				originAS:      70000,
				as4Path:       []uint32{70000},
				as4PathCount:  1,
				as4Aggregator: as4Aggregator,
			},
		},
		{
			name: "AGGREGATOR not AS_TRANS with AS4_AGGREGATOR: AS4_PATH ignored",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, seg2(asSequence, 100, ASTrans)),
				pathAttr(7, []byte{0, 200, 10, 0, 0, 1}),
				pathAttr(17, seg4(asSequence, 70000)),
				pathAttr(18, as4Aggregator),
			),
			want: asPathResult{
				segments:      []ASPathSegment{seq(100, ASTrans)},
				asPath:        []uint32{100, ASTrans},
				asPathCount:   2,
				originAS:      ASTrans,
				as4Path:       []uint32{70000},
				as4PathCount:  1,
				as4Aggregator: as4Aggregator,
			},
		},
		{
			// RFC 6793 Section 6: the 6-octet AS4_AGGREGATOR is discarded,
			// so the AGGREGATOR rule does not apply.
			name: "malformed AS4_AGGREGATOR with AGGREGATOR not AS_TRANS: merged",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, seg2(asSequence, 100, ASTrans)),
				pathAttr(7, []byte{0, 200, 10, 0, 0, 1}),
				pathAttr(17, seg4(asSequence, 70000)),
				pathAttr(18, []byte{0x11, 0x70, 10, 0, 0, 1}),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(100, 70000)},
				asPath:       []uint32{100, 70000},
				asPathCount:  2,
				originAS:     70000,
				as4Path:      []uint32{70000},
				as4PathCount: 1,
			},
		},
		{
			// RFC 7606 Section 7.7: an 8-octet AGGREGATOR on a 2-octet
			// session is malformed and treated as absent.
			name: "wrong-length AGGREGATOR: merged",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, seg2(asSequence, 100, ASTrans)),
				pathAttr(7, []byte{0, 0, 0, 200, 10, 0, 0, 1}),
				pathAttr(17, seg4(asSequence, 70000)),
				pathAttr(18, as4Aggregator),
			),
			want: asPathResult{
				segments:      []ASPathSegment{seq(100, 70000)},
				asPath:        []uint32{100, 70000},
				asPathCount:   2,
				originAS:      70000,
				as4Path:       []uint32{70000},
				as4PathCount:  1,
				as4Aggregator: as4Aggregator,
			},
		},
		{
			// RFC 6793 Section 4.2.3 applies the AGGREGATOR rule only when
			// both aggregator attributes are received.
			name: "AGGREGATOR not AS_TRANS without AS4_AGGREGATOR: merged",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, seg2(asSequence, 100, ASTrans)),
				pathAttr(7, []byte{0, 200, 10, 0, 0, 1}),
				pathAttr(17, seg4(asSequence, 70000)),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(100, 70000)},
				asPath:       []uint32{100, 70000},
				asPathCount:  2,
				originAS:     70000,
				as4Path:      []uint32{70000},
				as4PathCount: 1,
			},
		},
		{
			name: "AS4_PATH longer than AS_PATH: ignored",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, seg2(asSequence, ASTrans)),
				pathAttr(17, seg4(asSequence, 70000, 80000)),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(ASTrans)},
				asPath:       []uint32{ASTrans},
				asPathCount:  1,
				originAS:     ASTrans,
				as4Path:      []uint32{70000, 80000},
				as4PathCount: 2,
			},
		},
		{
			name: "confed segments in AS4_PATH are discarded",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, seg2(asSequence, 100, ASTrans)),
				pathAttr(17, concat(seg4(asConfedSequence, 65001), seg4(asSequence, 70000))),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(100, 70000)},
				asPath:       []uint32{100, 70000},
				asPathCount:  2,
				originAS:     70000,
				as4Path:      []uint32{70000},
				as4PathCount: 1,
			},
		},
		{
			name: "AS4_PATH of only confed segments is not used",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, concat(seg2(asSequence, 100), seg2(asSequence, ASTrans))),
				pathAttr(17, seg4(asConfedSequence, 65001)),
			),
			want: asPathResult{
				segments:    []ASPathSegment{seq(100), seq(ASTrans)},
				asPath:      []uint32{100, ASTrans},
				asPathCount: 2,
				originAS:    ASTrans,
			},
		},
		{
			name: "truncated AS4_PATH is discarded",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, seg2(asSequence, 100, ASTrans)),
				pathAttr(17, []byte{asSequence, 2, 0, 1, 0x11, 0x70}),
			),
			want: asPathResult{
				segments:    []ASPathSegment{seq(100, ASTrans)},
				asPath:      []uint32{100, ASTrans},
				asPathCount: 2,
				originAS:    ASTrans,
			},
		},
		{
			name: "AS4_PATH with zero-length segment is discarded",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, seg2(asSequence, 100, ASTrans)),
				pathAttr(17, concat(seg4(asSequence), seg4(asSequence, 70000))),
			),
			want: asPathResult{
				segments:    []ASPathSegment{seq(100, ASTrans)},
				asPath:      []uint32{100, ASTrans},
				asPathCount: 2,
				originAS:    ASTrans,
			},
		},
		{
			name: "AS4_PATH with invalid segment type is discarded",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, seg2(asSequence, 100, ASTrans)),
				pathAttr(17, seg4(5, 70000)),
			),
			want: asPathResult{
				segments:    []ASPathSegment{seq(100, ASTrans)},
				asPath:      []uint32{100, ASTrans},
				asPathCount: 2,
				originAS:    ASTrans,
			},
		},
		{
			name: "empty AS4_PATH is discarded",
			as4:  &as2,
			attrs: concat(
				pathAttr(2, seg2(asSequence, 100, ASTrans)),
				pathAttr(17, nil),
			),
			want: asPathResult{
				segments:    []ASPathSegment{seq(100, ASTrans)},
				asPath:      []uint32{100, ASTrans},
				asPathCount: 2,
				originAS:    ASTrans,
			},
		},
		{
			// RFC 7854 Section 4.2: the BMP speaker may reformat a 2-octet
			// AS_PATH into the 4-byte format (A flag 0).
			name: "4-octet AS_PATH with AS_TRANS: merged",
			as4:  &as4,
			attrs: concat(
				pathAttr(2, seg4(asSequence, 100, ASTrans)),
				pathAttr(17, seg4(asSequence, 70000)),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(100, 70000)},
				asPath:       []uint32{100, 70000},
				asPathCount:  2,
				originAS:     70000,
				as4Path:      []uint32{70000},
				as4PathCount: 1,
			},
		},
		{
			name: "4-octet AS_PATH with AS_TRANS, 8-octet AGGREGATOR AS_TRANS: merged",
			as4:  &as4,
			attrs: concat(
				pathAttr(2, seg4(asSequence, 100, ASTrans)),
				pathAttr(7, []byte{0, 0, 0x5B, 0xA0, 10, 0, 0, 1}),
				pathAttr(17, seg4(asSequence, 70000)),
				pathAttr(18, as4Aggregator),
			),
			want: asPathResult{
				segments:      []ASPathSegment{seq(100, 70000)},
				asPath:        []uint32{100, 70000},
				asPathCount:   2,
				originAS:      70000,
				as4Path:       []uint32{70000},
				as4PathCount:  1,
				as4Aggregator: as4Aggregator,
			},
		},
		{
			name: "4-octet AS_PATH with AS_TRANS, 8-octet AGGREGATOR not AS_TRANS: AS4_PATH ignored",
			as4:  &as4,
			attrs: concat(
				pathAttr(2, seg4(asSequence, 100, ASTrans)),
				pathAttr(7, []byte{0, 0, 0, 200, 10, 0, 0, 1}),
				pathAttr(17, seg4(asSequence, 70000)),
				pathAttr(18, as4Aggregator),
			),
			want: asPathResult{
				segments:      []ASPathSegment{seq(100, ASTrans)},
				asPath:        []uint32{100, ASTrans},
				asPathCount:   2,
				originAS:      ASTrans,
				as4Path:       []uint32{70000},
				as4PathCount:  1,
				as4Aggregator: as4Aggregator,
			},
		},
		{
			// AS4_PATH would replace 100, not the AS_TRANS before it.
			name: "4-octet AS_PATH with AS_TRANS only in the kept part: AS4_PATH ignored",
			as4:  &as4,
			attrs: concat(
				pathAttr(2, seg4(asSequence, ASTrans, 100)),
				pathAttr(17, seg4(asSequence, 4200000001)),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(ASTrans, 100)},
				asPath:       []uint32{ASTrans, 100},
				asPathCount:  2,
				originAS:     100,
				as4Path:      []uint32{4200000001},
				as4PathCount: 1,
			},
		},
		{
			name: "4-octet AS_PATH with AS_TRANS in an AS_SET it replaces: merged",
			as4:  &as4,
			attrs: concat(
				pathAttr(2, concat(seg4(asSequence, 100), seg4(asConfedSequence, 65001), seg4(asSet, 200, ASTrans))),
				pathAttr(17, seg4(asSet, 200, 4200000001)),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(100), confedSeq(65001), set(200, 4200000001)},
				asPath:       []uint32{100, 65001, 200, 4200000001},
				asPathCount:  4,
				originAS:     0,
				as4Path:      []uint32{200, 4200000001},
				as4PathCount: 2,
			},
		},
		{
			// RFC 6793 Section 6: AS4_PATH between NEW speakers is not used,
			// but is still reported.
			name: "4-octet AS_PATH without AS_TRANS: AS4_PATH ignored",
			as4:  &as4,
			attrs: concat(
				pathAttr(2, seg4(asSequence, 100, 200)),
				pathAttr(17, seg4(asSequence, 70000)),
			),
			want: asPathResult{
				segments:     []ASPathSegment{seq(100, 200)},
				asPath:       []uint32{100, 200},
				asPathCount:  2,
				originAS:     200,
				as4Path:      []uint32{70000},
				as4PathCount: 1,
			},
		},
		{
			name: "4-octet session: segments kept as received",
			as4:  &as4,
			attrs: pathAttr(2, concat(
				seg4(asConfedSequence, 65001, 65002),
				seg4(asConfedSet, 65003, 65004),
				seg4(asSet, 300, 400),
				seg4(asSequence, 100),
				seg4(asSequence, 200),
			)),
			want: asPathResult{
				segments: []ASPathSegment{
					confedSeq(65001, 65002),
					{Type: asConfedSet, ASNs: []uint32{65003, 65004}},
					set(300, 400),
					seq(100),
					seq(200),
				},
				asPath:      []uint32{65001, 65002, 65003, 65004, 300, 400, 100, 200},
				asPathCount: 8,
				originAS:    200,
			},
		},
		{
			name:  "path ending in AS_SET: no origin",
			as4:   &as4,
			attrs: pathAttr(2, concat(seg4(asSequence, 100), seg4(asSet, 200, 300))),
			want: asPathResult{
				segments:    []ASPathSegment{seq(100), set(200, 300)},
				asPath:      []uint32{100, 200, 300},
				asPathCount: 3,
				originAS:    0,
			},
		},
		{
			name:  "path ending in AS_CONFED_SEQUENCE: origin is the speaker's AS",
			as4:   &as4,
			attrs: pathAttr(2, concat(seg4(asSequence, 100), seg4(asConfedSequence, 65001))),
			want: asPathResult{
				segments:    []ASPathSegment{seq(100), confedSeq(65001)},
				asPath:      []uint32{100, 65001},
				asPathCount: 2,
				originAS:    testOwnAS,
			},
		},
		{
			name:  "empty AS_PATH: origin is the speaker's AS",
			as4:   &as4,
			attrs: pathAttr(2, nil),
			want: asPathResult{
				segments: []ASPathSegment{},
				asPath:   []uint32{},
				originAS: testOwnAS,
			},
		},
		{
			name:  "AS4_PATH without AS_PATH: no path, no origin",
			as4:   &as2,
			attrs: pathAttr(17, seg4(asSequence, 70000)),
			want: asPathResult{
				as4Path:      []uint32{70000},
				as4PathCount: 1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeASPathResult(t, tt.attrs, tt.as4); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestBaseAttributesOriginAS(t *testing.T) {
	tests := []struct {
		name     string
		segments []ASPathSegment
		want     uint32
	}{
		{"no AS_PATH", nil, 0},
		{"empty AS_PATH", []ASPathSegment{}, testOwnAS},
		{"final AS_SEQUENCE", []ASPathSegment{set(1, 2), seq(3, 4)}, 4},
		{"final AS_SET", []ASPathSegment{seq(3), set(1, 2)}, 0},
		{"final AS_CONFED_SEQUENCE", []ASPathSegment{seq(3), confedSeq(65001)}, testOwnAS},
		{"final AS_CONFED_SET", []ASPathSegment{{Type: asConfedSet, ASNs: []uint32{65001}}}, testOwnAS},
		{"final AS_SEQUENCE empty", []ASPathSegment{seq(3), seq()}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ba := &BaseAttributes{ASPathSegments: tt.segments}
			if got := ba.OriginAS(testOwnAS); got != tt.want {
				t.Errorf("OriginAS(%d) = %d, want %d", testOwnAS, got, tt.want)
			}
		})
	}
	// An unknown speaker AS leaves the origin unknown.
	ba := &BaseAttributes{ASPathSegments: []ASPathSegment{confedSeq(65001)}}
	if got := ba.OriginAS(0); got != 0 {
		t.Errorf("OriginAS(0) = %d, want 0", got)
	}
}

// mergeAS4Path must not write to the decoded AS_PATH segments it joins.
func TestMergeAS4PathDoesNotAlias(t *testing.T) {
	asns := make([]uint32, 1, 4)
	asns[0] = 100
	spare := asns[:2]
	spare[1] = 7
	asPath := []ASPathSegment{{Type: asSequence, ASNs: asns}, seq(ASTrans)}
	merged := mergeAS4Path(asPath, []ASPathSegment{seq(70000)})
	if want := []ASPathSegment{seq(100, 70000)}; !reflect.DeepEqual(merged, want) {
		t.Fatalf("merged = %v, want %v", merged, want)
	}
	if spare[1] != 7 {
		t.Errorf("AS_PATH segment's array modified: %v", spare)
	}
}

// RFC 6368 Section 5: AS_PATH inside ATTR_SET is always 4-octet.
func TestUnmarshalAttrSet_FourOctetASPath(t *testing.T) {
	originAS := []byte{0, 0, 0xFD, 0xE8}
	t.Run("4-octet AS_PATH, AS4_PATH ignored", func(t *testing.T) {
		as, err := UnmarshalAttrSet(concat(originAS,
			pathAttr(2, seg4(asSequence, 100, 200)),
			pathAttr(17, seg4(asSequence, 70000)),
		))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got, want := as.PathAttributes.ASPath, []uint32{100, 200}; !reflect.DeepEqual(got, want) {
			t.Errorf("ASPath = %v, want %v", got, want)
		}
	})
	t.Run("2-octet AS_PATH rejected", func(t *testing.T) {
		// Parses only with 2-octet ASNs; it was decoded as [100, 70000].
		as, err := UnmarshalAttrSet(concat(originAS,
			pathAttr(2, seg2(asSequence, 100, ASTrans)),
			pathAttr(17, seg4(asSequence, 70000)),
		))
		if err == nil {
			t.Errorf("got %+v, want error", as.PathAttributes)
		}
	})
}
