package message

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// baseAttrsMessageTypes returns a new value of every message type with a
// BaseAttributes field.
func baseAttrsMessageTypes() []baseAttrsHolder {
	return []baseAttrsHolder{
		&UnicastPrefix{}, &L3VPNPrefix{}, &MulticastPrefix{},
		&MCASTVPNPrefix{}, &RTCPrefix{}, &MUPPrefix{}, &EVPNPrefix{}, &VPLSPrefix{},
		&SRPolicy{}, &Flowspec{},
	}
}

// TestBaseAttrsHolders finds every struct of the package with a
// *bgp.BaseAttributes field, directly or by embedding, and checks it is in
// baseAttrsMessageTypes, which TestMarshalMessageAllTypes checks.
func TestBaseAttrsHolders(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	structs := make(map[string]*ast.StructType)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), e.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if ts, ok := n.(*ast.TypeSpec); ok {
				if st, ok := ts.Type.(*ast.StructType); ok {
					structs[ts.Name.Name] = st
				}
			}
			return true
		})
	}
	holders := make(map[string]bool)
	for changed := true; changed; {
		changed = false
		for name, st := range structs {
			for _, f := range st.Fields.List {
				typ := f.Type
				if star, ok := typ.(*ast.StarExpr); ok {
					if sel, ok := star.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "BaseAttributes" && len(f.Names) == 1 && f.Names[0].IsExported() && !holders[name] {
						holders[name], changed = true, true
					}
					typ = star.X
				}
				if id, ok := typ.(*ast.Ident); ok && len(f.Names) == 0 && holders[id.Name] && !holders[name] {
					holders[name], changed = true, true
				}
			}
		}
	}
	listed := make(map[string]bool)
	for _, m := range baseAttrsMessageTypes() {
		listed[reflect.TypeOf(m).Elem().Name()] = true
	}
	for name := range holders {
		if !listed[name] {
			t.Errorf("%s has a BaseAttributes field but is not in baseAttrsMessageTypes", name)
		}
	}
	if len(holders) != len(listed) {
		t.Errorf("found %d types with BaseAttributes, baseAttrsMessageTypes lists %d", len(holders), len(listed))
	}
}

// TestBaseAttrsFieldOrder checks every message type encodes base_attrs, from
// the field baseAttrsField returns, after keys of precedesBaseAttrs only and
// before a key it never omits, and is no json.Marshaler, which
// marshalMessage would not splice.
func TestBaseAttrsFieldOrder(t *testing.T) {
	for _, m := range baseAttrsMessageTypes() {
		typ := reflect.TypeOf(m).Elem()
		if _, ok := m.(json.Marshaler); ok {
			t.Errorf("%s is a json.Marshaler", typ)
		}
		if _, ok := m.(encoding.TextMarshaler); ok {
			t.Errorf("%s is an encoding.TextMarshaler", typ)
		}
		seen, after, next := false, false, ""
		for _, f := range reflect.VisibleFields(typ) {
			tag := f.Tag.Get("json")
			name, opts, _ := strings.Cut(tag, ",")
			if f.Anonymous && name == "" || tag == "-" || !f.IsExported() {
				continue
			}
			switch {
			case name == "base_attrs":
				if tag != "base_attrs,omitempty" || f.Type != reflect.TypeOf((*bgp.BaseAttributes)(nil)) || seen {
					t.Errorf("%s: field %s tagged %q", typ, f.Name, tag)
				}
				v := reflect.ValueOf(m).Elem().FieldByIndex(f.Index)
				if v.Addr().Interface() != any(m.baseAttrsField()) {
					t.Errorf("%s: baseAttrsField is not field %s", typ, f.Name)
				}
				seen = true
			case !seen && !precedesBaseAttrs([]byte(name)):
				t.Errorf("%s: %s is encoded before base_attrs", typ, name)
			case seen && precedesBaseAttrs([]byte(name)):
				t.Errorf("%s: %s is encoded after base_attrs", typ, name)
			case seen && !after:
				after = !strings.Contains(opts, "omitempty")
				next = name
			}
		}
		if !seen || !after {
			t.Errorf("%s: base_attrs found %v, followed by a key never omitted %v (%s)", typ, seen, after, next)
		}
	}
}

// marshalled returns what f returns, or the panic it raises as an error.
func marshalled(f func() ([]byte, error)) (b []byte, err error, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			err, panicked = fmt.Errorf("panic: %v", r), true
		}
	}()
	b, err = f()
	return b, err, false
}

// checkSpliced fails unless marshalMessage returns, or panics, as
// json.Marshal(m) for each of msgs in turn, while on, and splices the
// base_attrs of all but the first when they share it.
func checkSpliced(t *testing.T, what string, msgs ...any) {
	t.Helper()
	c := baseAttrsCache{on: true}
	prevOK := false
	for i, m := range msgs {
		want, wantErr, wantPanic := marshalled(func() ([]byte, error) { return json.Marshal(m) })
		got, err, panicked := marshalled(func() ([]byte, error) { return marshalMessage(m, &c) })
		if (err != nil) != (wantErr != nil) || panicked != wantPanic || !bytes.Equal(got, want) {
			t.Fatalf("%s: route %d: marshalMessage() = %s, %v\nwant %s, %v", what, i, got, err, want, wantErr)
		}
		if prevOK && wantErr == nil && c.attrs != nil && c.value == nil {
			t.Fatalf("%s: route %d: base_attrs of %T not spliced", what, i, m)
		}
		prevOK = wantErr == nil
	}
}

// fill sets the exported fields of v, recursively to depth, each with
// probability p, to values encoding/json does not omit, strings that need
// escaping, but not the BaseAttributes fields.
func fill(r *rand.Rand, v reflect.Value, depth int, p float64) {
	if r.Float64() >= p && v.Kind() != reflect.Struct {
		return
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString([]string{"a\"<&>\\ é", "base_attrs", `"base_attrs":{}`, "x"}[r.Intn(4)])
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(r.Intn(100) - 50))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(r.Intn(100)))
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1.5)
	case reflect.Pointer:
		if depth > 0 && v.Type() != reflect.TypeOf((*bgp.BaseAttributes)(nil)) {
			v.Set(reflect.New(v.Type().Elem()))
			fill(r, v.Elem(), depth-1, p)
		}
	case reflect.Slice:
		if depth > 0 {
			v.Set(reflect.MakeSlice(v.Type(), 1+r.Intn(2), 2))
			for i := 0; i < v.Len(); i++ {
				fill(r, v.Index(i), depth-1, p)
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				fill(r, v.Field(i), depth, p)
			}
		}
	}
}

// baseAttrsVariants returns no, empty and escaping BaseAttributes and those
// of the matrix's UPDATEs.
func baseAttrsVariants(t testing.TB) []*bgp.BaseAttributes {
	vs := []*bgp.BaseAttributes{nil, {}, {Origin: "igp", CommunityList: []string{"a\"<&>\\ é"}, AS4Aggregator: []byte{0xff}}}
	for _, c := range afiBenchCases() {
		u, err := bgp.UnmarshalBGPUpdateWithAS4Hint(c.update, true)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		vs = append(vs, u.BaseAttributes)
	}
	return vs
}

// routes returns n messages of the type of proto, filled with probability p,
// sharing attrs, passed as the producer does, by pointer and by pointer to
// pointer.
func routes(r *rand.Rand, proto baseAttrsHolder, attrs *bgp.BaseAttributes, n int, p float64) ([]any, []any) {
	var byPtr, byPtrPtr []any
	for i := 0; i < n; i++ {
		v := reflect.New(reflect.TypeOf(proto).Elem())
		fill(r, v.Elem(), 3, p)
		m := v.Interface().(baseAttrsHolder)
		*m.baseAttrsField() = attrs
		pp := reflect.New(v.Type())
		pp.Elem().Set(v)
		byPtr, byPtrPtr = append(byPtr, m), append(byPtrPtr, pp.Interface())
	}
	return byPtr, byPtrPtr
}

// TestMarshalMessageAllTypes checks every message type, empty or filled,
// with every BaseAttributes variant, 1 to 3 routes.
func TestMarshalMessageAllTypes(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for _, proto := range baseAttrsMessageTypes() {
		for _, p := range []float64{0, 1} {
			for _, attrs := range baseAttrsVariants(t) {
				for n := 1; n <= 3; n++ {
					byPtr, byPtrPtr := routes(r, proto, attrs, n, p)
					what := reflect.TypeOf(proto).String()
					checkSpliced(t, what, byPtr...)
					checkSpliced(t, what+" by pointer to pointer", byPtrPtr...)
				}
			}
		}
	}
}

// TestMarshalMessageRandom compares marshalMessage with json.Marshal for
// random messages of random types, fields set at random.
func TestMarshalMessageRandom(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	types, attrs := baseAttrsMessageTypes(), baseAttrsVariants(t)
	for i := 0; i < 2000; i++ {
		byPtr, byPtrPtr := routes(r, types[r.Intn(len(types))], attrs[r.Intn(len(attrs))], 1+r.Intn(5), r.Float64())
		if r.Intn(2) == 0 {
			byPtr = byPtrPtr
		}
		checkSpliced(t, "random", byPtr...)
	}
}

// TestMarshalMessageMatrix checks the messages the matrix publishes, decoded
// into their types and given one BaseAttributes.
func TestMarshalMessageMatrix(t *testing.T) {
	types := map[int]func() any{
		bmp.UnicastPrefixV4Msg: func() any { return &UnicastPrefix{} }, bmp.UnicastPrefixV6Msg: func() any { return &UnicastPrefix{} },
		bmp.L3VPNV4Msg: func() any { return &L3VPNPrefix{} }, bmp.L3VPNV6Msg: func() any { return &L3VPNPrefix{} },
		bmp.EVPNMsg:        func() any { return &EVPNPrefix{} },
		bmp.MulticastV4Msg: func() any { return &MulticastPrefix{} }, bmp.MCASTVPNV4Msg: func() any { return &MCASTVPNPrefix{} },
		bmp.RTCV4Msg: func() any { return &RTCPrefix{} }, bmp.MUPV4Msg: func() any { return &MUPPrefix{} },
		bmp.VPLSMsg: func() any { return &VPLSPrefix{} }, bmp.SRPolicyV4Msg: func() any { return &SRPolicy{} },
		bmp.FlowspecV4Msg: func() any { return &Flowspec{} },
	}
	for _, c := range afiBenchCases() {
		ph := afiBenchHeader()
		pub := &recordingPublisher{}
		p := NewProducer(pub, true).(*producer)
		p.producingWorker(benchPeerUp(ph))
		n := len(pub.msgs)
		p.producingWorker(afiBenchMessage(t, ph, c))
		var msgs []any
		var attrs *bgp.BaseAttributes
		for _, m := range pub.msgs[n:] {
			newMsg, ok := types[m.msgType]
			if !ok {
				if bytes.Contains(m.payload, baseAttrsKey) {
					t.Fatalf("%s: message type %d has base_attrs", c.name, m.msgType)
				}
				continue
			}
			v := newMsg()
			if err := json.Unmarshal(m.payload, v); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			h := v.(baseAttrsHolder)
			if attrs == nil {
				attrs = *h.baseAttrsField()
			}
			*h.baseAttrsField() = attrs
			msgs = append(msgs, v)
		}
		checkSpliced(t, c.name, msgs...)
	}
}

// marshalerHolder is a message type that encodes itself.
type marshalerHolder struct {
	BaseAttributes *bgp.BaseAttributes `json:"base_attrs,omitempty"`
}

func (m *marshalerHolder) baseAttrsField() **bgp.BaseAttributes { return &m.BaseAttributes }
func (m *marshalerHolder) MarshalJSON() ([]byte, error)         { return []byte(`{"own":1}`), nil }

// panicHolder is a message type whose encoding panics when it is set to.
type panicHolder struct {
	Router         string              `json:"router_ip"`
	BaseAttributes *bgp.BaseAttributes `json:"base_attrs,omitempty"`
	Panic          panicValue          `json:"p"`
}

type panicValue bool

func (p panicValue) MarshalJSON() ([]byte, error) {
	if p {
		panic("panicValue")
	}
	return []byte("0"), nil
}

func (m *panicHolder) baseAttrsField() **bgp.BaseAttributes { return &m.BaseAttributes }

// TestMarshalMessageRefusesAndRestores checks marshalMessage does not splice
// a json.Marshaler, nor while off, and restores the BaseAttributes of a
// message whose encoding panics.
func TestMarshalMessageRefusesAndRestores(t *testing.T) {
	attrs := &bgp.BaseAttributes{Origin: "igp"}
	c := baseAttrsCache{on: true}
	for i := 0; i < 2; i++ {
		if got, _ := marshalMessage(&marshalerHolder{BaseAttributes: attrs}, &c); string(got) != `{"own":1}` || c.attrs != nil {
			t.Fatalf("json.Marshaler: got %s, cache %+v", got, c)
		}
	}
	var off baseAttrsCache
	for i := 0; i < 2; i++ {
		marshalMessage(&UnicastPrefix{BaseAttributes: attrs}, &off)
	}
	if off.attrs != nil {
		t.Fatalf("cache used while off: %+v", off)
	}
	m := &panicHolder{BaseAttributes: attrs}
	if _, err := marshalMessage(m, &c); err != nil {
		t.Fatal(err)
	}
	m.Panic = true
	func() {
		defer func() { recover() }()
		marshalMessage(m, &c)
	}()
	if m.BaseAttributes != attrs {
		t.Fatalf("BaseAttributes not restored after a panic: %v", m.BaseAttributes)
	}
}

// TestBaseAttrsAt checks baseAttrsAt on objects encoding/json does and does
// not write.
func TestBaseAttrsAt(t *testing.T) {
	for j, want := range map[string]int{
		``: -1, `[]`: -1, `{`: -1, `{"hash"`: -1, `{"hash":`: -1, `{"hash":"x`: -1, `{"hash":1`: -1,
		`{}`: 1, `{"x":1}`: 1, `{"hash":1}`: 9, `{"hash":"a\"}","x":2}`: 15, `{"_key":"k","hash":{"a":[1,"}"]},"x":2}`: 33,
	} {
		if got := baseAttrsAt([]byte(j)); got != want {
			t.Errorf("baseAttrsAt(%q) = %d, want %d", j, got, want)
		}
	}
}

// BenchmarkMarshalMessage times marshalMessage against json.Marshal for the
// routes of one IPv4 unicast UPDATE.
func BenchmarkMarshalMessage(b *testing.B) {
	attrs := baseAttrsVariants(b)[4]
	for _, n := range []int{1, 2, 3, 4, 8, 64} {
		msgs := make([]*UnicastPrefix, n)
		for i := range msgs {
			msgs[i] = &UnicastPrefix{Action: "add", Hash: "971e635b94eca8f9697eaf86d6d4fc1d", RouterHash: "66efff4c945d3c3b87fc271b47d456db",
				RouterIP: "192.168.1.1", BaseAttributes: attrs, PeerHash: "79c56ab0db70cf69163c11ad4f16def2", RemoteBGPID: "10.0.0.1",
				PeerIP: "192.0.2.1", PeerASN: 65000, Timestamp: "2025-04-16T19:07:44.065536Z", Prefix: "10.0.0.0", PrefixLen: 24,
				IsIPv4: true, OriginAS: 13335, Nexthop: "192.0.2.1", IsNexthopIPv4: true}
		}
		for _, splice := range []bool{false, true} {
			name := map[bool]string{false: "json.Marshal", true: "marshalMessage"}[splice]
			b.Run(fmt.Sprintf("%s/routes=%d", name, n), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					c := baseAttrsCache{on: splice}
					for _, m := range msgs {
						if _, err := marshalMessage(&m, &c); err != nil {
							b.Fatal(err)
						}
					}
				}
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*n), "ns/route")
			})
		}
	}
}
