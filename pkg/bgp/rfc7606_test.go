package bgp

import (
	"reflect"
	"testing"
)

// RFC 7606 Section 3(g): repeated attributes after the first are discarded,
// except MP_REACH_NLRI and MP_UNREACH_NLRI.
func TestUnmarshalRawPathAttributes_Repeated(t *testing.T) {
	b := concat(
		pathAttr(1, []byte{0}),
		pathAttr(14, []byte{1}),
		pathAttr(1, []byte{2}),
		pathAttr(99, []byte{3}),
		pathAttr(14, []byte{4}),
		pathAttr(15, []byte{5}),
		pathAttr(15, []byte{6}),
		pathAttr(99, []byte{7}),
	)
	attrs, err := unmarshalRawPathAttributes(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got [][2]byte
	for _, a := range attrs {
		got = append(got, [2]byte{a.AttributeType, a.Attribute[0]})
	}
	want := [][2]byte{{1, 0}, {14, 1}, {99, 3}, {14, 4}, {15, 5}, {15, 6}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got (type, value) %v, want %v", got, want)
	}
}

func TestUnmarshalBaseAttributes_RepeatedAttributes(t *testing.T) {
	as2 := false
	t.Run("COMMUNITY: first wins, hash ignores the repeat", func(t *testing.T) {
		first := pathAttr(8, []byte{0xFD, 0xE8, 0, 1})  // 65000:1
		second := pathAttr(8, []byte{0xFD, 0xE8, 0, 2}) // 65000:2
		asPath := pathAttr(2, seg4(asSequence, 100))
		_, got, err := unmarshalBGPPathAttributes(concat(asPath, first, second), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_, want, err := unmarshalBGPPathAttributes(concat(asPath, first), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got.CommunityList, []string{"65000:1"}) {
			t.Errorf("CommunityList = %v, want [65000:1]", got.CommunityList)
		}
		if got.BaseAttrHash != want.BaseAttrHash {
			t.Errorf("BaseAttrHash = %s, want %s (UPDATE without the repeat)", got.BaseAttrHash, want.BaseAttrHash)
		}
	})
	t.Run("AS4_PATH: malformed first is discarded with the repeat", func(t *testing.T) {
		got := decodeASPathResult(t, concat(
			pathAttr(2, seg2(asSequence, 100, ASTrans)),
			pathAttr(17, seg4(5, 70000)),
			pathAttr(17, seg4(asSequence, 70000)),
		), &as2)
		want := asPathResult{
			segments:    []ASPathSegment{seq(100, ASTrans)},
			asPath:      []uint32{100, ASTrans},
			asPathCount: 2,
			originAS:    ASTrans,
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got  %+v\nwant %+v", got, want)
		}
	})
	t.Run("AS4_PATH: first wins", func(t *testing.T) {
		got := decodeASPathResult(t, concat(
			pathAttr(2, seg2(asSequence, 100, ASTrans)),
			pathAttr(17, seg4(asSequence, 70000)),
			pathAttr(17, seg4(asSequence, 80000)),
		), &as2)
		want := asPathResult{
			segments:     []ASPathSegment{seq(100, 70000)},
			asPath:       []uint32{100, 70000},
			asPathCount:  2,
			originAS:     70000,
			as4Path:      []uint32{70000},
			as4PathCount: 1,
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got  %+v\nwant %+v", got, want)
		}
	})
}
