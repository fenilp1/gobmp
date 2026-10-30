package bgp

import (
	"bytes"
	"testing"
)

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

// Malformed Multiprotocol (RFC 4760 §8) and BGP Role (RFC 9234 §4.1)
// capabilities are kept raw and undecoded; the getters ignore them and the
// OPEN and its other capabilities survive.
func TestUnmarshalBGPOpenMessage_MalformedCapabilityKeptRaw(t *testing.T) {
	o, err := UnmarshalBGPOpenMessage(openWithParams(
		0x02, 0x05, 0x01, 0x03, 0x00, 0x01, 0x00, // MP, length 3
		0x02, 0x02, 0x09, 0x00, // Role, length 0
		0x02, 0x06, 0x45, 0x04, 0x00, 0x01, 0x01, 0x03, // ADD-PATH IPv4 unicast
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for code, want := range map[uint8]struct {
		value []byte
		descr string
	}{
		1: {[]byte{0x00, 0x01, 0x00}, BGPCapabilities[1]},
		9: {[]byte{}, BGPCapabilities[9]},
	} {
		c := o.Capabilities[code]
		if len(c) != 1 || !bytes.Equal(c[0].Value, want.value) || c[0].Description != want.descr {
			t.Errorf("code %d: got %+v, want raw value %x with description %q", code, c, want.value, want.descr)
		}
	}
	if _, ok := o.BGPRoleCapability(); ok {
		t.Error("malformed Role capability reported as a Role")
	}
	if !o.AddPathCapability()[NLRIMessageType(1, 1)] {
		t.Error("ADD-PATH capability lost")
	}
}

// RFC 9234 §4.2: a malformed Role next to a valid one is a set of Roles that do
// not all have the same value, so both stay visible and no Role is reported.
func TestUnmarshalBGPOpenMessage_MalformedAndValidRole(t *testing.T) {
	o, err := UnmarshalBGPOpenMessage(openWithParams(0x02, 0x07, 0x09, 0x02, 0x00, 0x00, 0x09, 0x01, 0x03))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c := o.Capabilities[9]; len(c) != 2 || len(c[0].Value) != 2 || c[1].Description != BGPCapabilities[9]+" : Customer" {
		t.Errorf("Role capabilities = %+v, want malformed then Customer", c)
	}
	if r, ok := o.BGPRoleCapability(); ok {
		t.Errorf("BGPRoleCapability = %v, want none", r)
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
