package attrset_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/messier-42/cabe-go/attrset"
)

const testInvalidName = "1bad"

func TestValidName(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{"", false},
		{"a", true},
		{"A", true},
		{"abc", true},
		{"a1", true},
		{"a1b2", true},
		{"a-b", true},
		{"a-b-c", true},
		{"a--b", false},
		{"a-", false},
		{"-a", false},
		{"1a", false},
		{"a_b", false},
		{"a.b", false},
		{"a b", false},
		{"a" + strings.Repeat("b", 254), true},
		{"a" + strings.Repeat("b", 255), false},
	}
	for _, c := range cases {
		if got := attrset.ValidName(c.in); got != c.ok {
			t.Errorf("ValidName(%q) = %v, want %v", c.in, got, c.ok)
		}
	}
}

func TestNewZeroAndEmpty(t *testing.T) {
	var zero attrset.Set
	if zero.Len() != 0 {
		t.Errorf("zero Set Len = %d, want 0", zero.Len())
	}

	s, err := attrset.New(nil)
	if err != nil {
		t.Fatalf("New(nil) error: %v", err)
	}
	if s.Len() != 0 {
		t.Errorf("New(nil) Len = %d, want 0", s.Len())
	}

	s, err = attrset.New(map[string]any{})
	if err != nil {
		t.Fatalf("New({}) error: %v", err)
	}
	if s.Len() != 0 {
		t.Errorf("New({}) Len = %d, want 0", s.Len())
	}
}

func TestNewValidates(t *testing.T) {
	_, err := attrset.New(map[string]any{testInvalidName: "v"})
	if err == nil {
		t.Fatalf("New with invalid key: want error, got nil")
	}
	var invName *attrset.InvalidNameError
	if !errors.As(err, &invName) {
		t.Fatalf("error type = %T, want *attrset.InvalidNameError", err)
	}
	if invName.Name != testInvalidName {
		t.Fatalf("InvalidNameError.Name = %q, want %q", invName.Name, testInvalidName)
	}
	if _, err := attrset.New(map[string]any{"ok": "v", "also-ok": 1}); err != nil {
		t.Errorf("New with valid keys: error %v", err)
	}
}

func TestAccessors(t *testing.T) {
	m := map[string]any{
		"tenant": "acme",
		"level":  int64(3),
		"prod":   true,
	}
	s, err := attrset.New(m)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.Len() != 3 {
		t.Errorf("Len = %d, want 3", s.Len())
	}
	if v, ok := s.Get("tenant"); !ok || v != "acme" {
		t.Errorf("Get tenant = (%v, %v), want (acme, true)", v, ok)
	}
	if _, ok := s.Get("missing"); ok {
		t.Errorf("Get missing: want !ok")
	}
	if !s.Has("level") || s.Has("missing") {
		t.Errorf("Has: tenant=%v missing=%v", s.Has("level"), s.Has("missing"))
	}
	got := s.Names()
	want := []string{"level", "prod", "tenant"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Names = %v, want %v", got, want)
	}
}

func TestNewClonesInput(t *testing.T) {
	m := map[string]any{"a": 1}
	s, err := attrset.New(m)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m["a"] = 2
	m["b"] = 3
	if v, _ := s.Get("a"); v != 1 {
		t.Errorf("after mutating input, Get a = %v, want 1", v)
	}
	if s.Len() != 1 {
		t.Errorf("after mutating input, Len = %d, want 1", s.Len())
	}
}

func TestRange(t *testing.T) {
	s, _ := attrset.New(map[string]any{"a": 1, "b": 2, "c": 3})
	seen := map[string]any{}
	s.Range(func(k string, v any) bool {
		seen[k] = v
		return true
	})
	if !reflect.DeepEqual(seen, map[string]any{"a": 1, "b": 2, "c": 3}) {
		t.Errorf("Range collected %v", seen)
	}

	count := 0
	s.Range(func(k string, v any) bool {
		count++
		return false
	})
	if count != 1 {
		t.Errorf("Range early-stop count = %d, want 1", count)
	}
}

func TestRepr_EmptySet(t *testing.T) {
	s, _ := attrset.New(nil)
	r := s.Repr()
	if r != attrset.Repr("\xa0") {
		t.Fatalf("empty Repr = % x, want a0", []byte(r))
	}
}

func TestRepr_Deterministic(t *testing.T) {
	s1, _ := attrset.New(map[string]any{
		"b":       int64(2),
		"a":       int64(1),
		"charlie": int64(3),
	})
	s2, _ := attrset.New(map[string]any{
		"charlie": int64(3),
		"a":       int64(1),
		"b":       int64(2),
	})
	if s1.Repr() != s2.Repr() {
		t.Fatalf("different insertion orders produced different Repr: % x vs % x", []byte(s1.Repr()), []byte(s2.Repr()))
	}
}

func TestRepr_DistinguishesDifferentSets(t *testing.T) {
	a, _ := attrset.New(map[string]any{"k": "v1"})
	b, _ := attrset.New(map[string]any{"k": "v2"})
	if a.Repr() == b.Repr() {
		t.Fatalf("distinct Sets produced equal Repr: % x", []byte(a.Repr()))
	}
}

func TestReprDecodeRoundTrip(t *testing.T) {
	orig, err := attrset.New(map[string]any{
		"sensitivity": "secret",
		"country":     "GB",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := orig.Repr().Decode()
	if err != nil {
		t.Fatalf("Repr.Decode: %v", err)
	}
	if got.Repr() != orig.Repr() {
		t.Fatalf("round-trip Repr differs: % x vs % x", []byte(got.Repr()), []byte(orig.Repr()))
	}
}

func TestNewFromBytesEmptySet(t *testing.T) {
	s, err := attrset.NewFromBytes([]byte{0xa0})
	if err != nil {
		t.Fatalf("NewFromBytes: %v", err)
	}
	if s.Len() != 0 {
		t.Fatalf("Len = %d, want 0", s.Len())
	}
}

func TestNewFromBytesRejectsInvalid(t *testing.T) {
	if _, err := attrset.NewFromBytes(nil); err == nil {
		t.Fatal("nil accepted")
	}
	if _, err := attrset.NewFromBytes([]byte{0xff}); err == nil {
		t.Fatal("garbage accepted")
	}
	// Valid CBOR map with an invalid Attribute Set key (leading digit).
	invalid, _ := cbor.Marshal(map[string]any{testInvalidName: "v"})
	if _, err := attrset.NewFromBytes(invalid); err == nil {
		t.Fatal("invalid attrset key accepted")
	}
}

// TestNewFromBytesRejectsNonCanonical pins the "equality = byte-equality
// of Repr" invariant: any Repr that is not in Core Deterministic form
// must be rejected, even if it would decode to a perfectly valid Set.
func TestNewFromBytesRejectsNonCanonical(t *testing.T) {
	t.Run("unsorted keys", func(t *testing.T) {
		// Core Deterministic orders map keys by length-first, then
		// lexicographically. Two single-char keys "a" < "b", so the
		// canonical form is {"a", "b"}. Craft the reverse by hand:
		//   0xa2 (map, 2 pairs)
		//     0x61 'b' 0x02
		//     0x61 'a' 0x01
		bad := []byte{0xa2, 0x61, 'b', 0x02, 0x61, 'a', 0x01}
		if _, err := attrset.NewFromBytes(bad); err == nil {
			t.Fatal("non-canonical key order accepted")
		}
	})

	t.Run("non-minimal integer header", func(t *testing.T) {
		// Canonical encoding of the integer 1 is 0x01 (major 0,
		// argument 1). Encode 1 with a 1-byte argument (0x18 0x01)
		// which is non-minimal.
		bad := []byte{0xa1, 0x61, 'k', 0x18, 0x01}
		if _, err := attrset.NewFromBytes(bad); err == nil {
			t.Fatal("non-minimal integer header accepted")
		}
	})

	t.Run("indefinite-length map", func(t *testing.T) {
		bad := []byte{0xbf, 0x61, 'k', 0x01, 0xff}
		if _, err := attrset.NewFromBytes(bad); err == nil {
			t.Fatal("indefinite-length map accepted")
		}
	})

	t.Run("duplicate map keys", func(t *testing.T) {
		bad := []byte{0xa2, 0x61, 'k', 0x01, 0x61, 'k', 0x02}
		if _, err := attrset.NewFromBytes(bad); err == nil {
			t.Fatal("duplicate map keys accepted")
		}
	})
}

func TestMapIsClone(t *testing.T) {
	s, _ := attrset.New(map[string]any{"a": 1})
	m := s.Map()
	if m == nil || m["a"] != 1 {
		t.Fatalf("Map() = %v", m)
	}
	m["a"] = 2
	if v, _ := s.Get("a"); v != 1 {
		t.Fatalf("mutating Map() result affected Set: Get a = %v", v)
	}
}

func TestReprEqualityIsByteEquality(t *testing.T) {
	// Idiom: Set equality is expressed as Repr value equality (==).
	a, _ := attrset.New(map[string]any{"x": 1, "y": 2})
	b, _ := attrset.New(map[string]any{"y": 2, "x": 1})
	if a.Repr() != b.Repr() {
		t.Fatal("equal sets produced unequal Repr")
	}
}
