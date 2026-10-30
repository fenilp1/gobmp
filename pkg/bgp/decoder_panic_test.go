package bgp

import "testing"

// openWithParams builds a BGP OPEN (without marker), My AS 65000, carrying
// the given optional parameters.
func openWithParams(opt ...byte) []byte {
	b := []byte{0, byte(29 + len(opt)), 0x01, 0x04, 0xfd, 0xe8, 0x00, 0xb4, 192, 0, 2, 1, byte(len(opt))}
	return append(b, opt...)
}

// A 4-octet AS capability (code 65) whose length is not 4 (RFC 6793 §3) used
// to panic in Is4BytesASCapable. The router already accepted the OPEN
// (RFC 7854 §4.10), so decode keeps it raw and the getter reports not capable.
func TestUnmarshalBGPOpenMessage_Cap65BadLength(t *testing.T) {
	for name, opt := range map[string][]byte{
		"length 0": {0x02, 0x02, 0x41, 0x00},
		"length 2": {0x02, 0x04, 0x41, 0x02, 0xfd, 0xe8},
		"length 5": {0x02, 0x07, 0x41, 0x05, 0x00, 0x00, 0xfd, 0xe8, 0x00},
	} {
		o, err := UnmarshalBGPOpenMessage(openWithParams(opt...))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		if len(o.Capabilities[65]) != 1 || len(o.Capabilities[65][0].Value) != int(opt[3]) {
			t.Errorf("%s: raw capability not kept: %+v", name, o.Capabilities[65])
		}
		if _, ok := o.Is4BytesASCapable(); ok {
			t.Errorf("%s: expected not 4-octet AS capable", name)
		}
	}
}

func TestIs4BytesASCapable_MalformedValue(t *testing.T) {
	for name, c := range map[string]Capability{
		"empty value": {65: {{Value: nil}}},
		"short value": {65: {{Value: []byte{0, 1}}}},
		"no entries":  {65: {}},
	} {
		o := &OpenMessage{Capabilities: c}
		if _, ok := o.Is4BytesASCapable(); ok {
			t.Errorf("%s: expected not capable", name)
		}
	}
	o := &OpenMessage{Capabilities: Capability{65: {{Value: []byte{0, 1, 0, 1}}}}}
	if as, ok := o.Is4BytesASCapable(); !ok || as != 65537 {
		t.Fatalf("got %d, %t; want 65537, true", as, ok)
	}
}

// BGP-LS attribute carrying an SRv6 SID Structure TLV (1252) of length 1
// (RFC 9514 §8 requires 4). GetSRv6SIDStructure used to panic.
func TestGetSRv6SIDStructure_ShortTLV(t *testing.T) {
	attrs := []byte{0x40, 0x01, 0x01, 0x00, 0x80, 0x1d, 0x05, 0x04, 0xe4, 0x00, 0x01, 0x00}
	u, err := UnmarshalBGPUpdate(append([]byte{0, 0, 0, byte(len(attrs))}, attrs...))
	if err != nil {
		t.Fatal(err)
	}
	ls, err := u.GetBGPLSAttribute()
	if err != nil {
		t.Fatal(err)
	}
	if s := ls.GetSRv6SIDStructure(); s != nil {
		t.Fatalf("expected nil SID structure, got %+v", s)
	}
}
