//nolint:goconst // Literal test inputs make the grammar and case distinctions visible.
package acp240

import (
	"errors"
	"reflect"
	"testing"

	"github.com/messier-42/cabe-go/attrset"
)

func makeSet(t *testing.T, m map[string]any) attrset.Set {
	t.Helper()
	set, err := attrset.New(m)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestPublishedRules(t *testing.T) {
	tests := []struct {
		name  string
		attrs map[string]any
		want  string // Invalid attribute; empty means structural success.
	}{
		{"missing policy", map[string]any{"s": "SECRET"}, "p"},
		{"missing sensitivity", map[string]any{"p": "PUBLIC"}, "s"},
		{"country lowercase", map[string]any{"p": "usa", "s": "SECRET"}, "p"},
		{"country length", map[string]any{"p": "US", "s": "SECRET"}, "p"},
		{"non ASCII policy literal", map[string]any{"p": "publıc", "s": "UNMARKED"}, "p"},
		{"lowercase sensitivity", map[string]any{"p": "USA", "s": "secret"}, "s"},
		{"lowercase without simple uppercase", map[string]any{"p": "USA", "s": "ß"}, "s"},
		{"national syntax", map[string]any{"p": "ZZZ", "s": "ÉLEVÉ", "c": "ALPHA,BRAVO", "o": "ALPHA"}, ""},
		{"national empty context", map[string]any{"p": "USA", "s": "SECRET", "c": ""}, ""},
		{"list type", map[string]any{"p": "PUBLIC", "s": "UNMARKED", "r": []string{"FVEY"}}, "r"},
		{"lowercase group", map[string]any{"p": "PUBLIC", "s": "UNMARKED", "r": "fvey"}, "r"},
		{"duplicate group", map[string]any{"p": "PUBLIC", "s": "UNMARKED", "r": "FVEY,FVEY"}, "r"},
		{"empty list item", map[string]any{"p": "PUBLIC", "s": "UNMARKED", "r": "FVEY,"}, "r"},
		{"group spacing grammar", map[string]any{"p": "PUBLIC", "s": "UNMARKED", "r": " GROUP  NAME "}, ""},
		{"noncanonical order", map[string]any{"p": "USA", "s": "SECRET", "c": "BRAVO,ALPHA"}, "c"},
		{"context spacing", map[string]any{"p": "USA", "s": "SECRET", "c": "ALPHA  BRAVO"}, "c"},
		{"NATO sensitivity despite case", map[string]any{"p": "nAtO", "s": "UNMARKED", "c": "EXERCISE"}, "s"},
		{"NATO cardinality despite case", map[string]any{"p": "nAtO", "s": "SECRET", "c": "ALPHA,BRAVO"}, "c"},
		{"NATO releasable", map[string]any{"p": "NATO", "s": "SECRET", "c": "RELEASABLE"}, "c"},
		{"PUBLIC sensitivity despite case", map[string]any{"p": "public", "s": "SECRET"}, "s"},
		{"PUBLIC context", map[string]any{"p": "PUBLIC", "s": "UNMARKED", "c": ""}, "c"},
		{"PUBLIC only", map[string]any{"p": "PUBLIC", "s": "UNMARKED", "o": "ALPHA"}, "o"},
		{"only requires context", map[string]any{"p": "USA", "s": "SECRET", "o": "ALPHA"}, "o"},
		{"only nonempty despite ABNF", map[string]any{"p": "USA", "s": "SECRET", "c": "ALPHA", "o": ""}, "o"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := makeSet(t, tt.attrs)
			err := (Profile{}).ValidateStructure(set)
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var fieldErr *ValidationError
				if !errors.As(err, &fieldErr) || fieldErr.Attribute != tt.want {
					t.Fatalf("error = %v, want attribute %s", err, tt.want)
				}
			}
			if !reflect.DeepEqual(set.Map(), tt.attrs) {
				t.Fatal("validation changed the Attribute Set")
			}
		})
	}
}

func TestPolicyValidation(t *testing.T) {
	// EXERCISE is test data, not a prescribed NATO context.
	rejected := errors.New("policy rejected the combination")
	for _, policy := range []string{"NATO", "nAtO", "USA"} {
		set := makeSet(t, map[string]any{"p": policy, "s": "SECRET", "c": "EXERCISE", "o": "ALPHA", "r": "FVEY"})
		if err := (Profile{}).Validate(set); !errors.Is(err, ErrPolicyRequired) {
			t.Fatalf("%s: got %v, want insufficient policy information", policy, err)
		}
		calls := 0
		profile := Profile{ValidatePolicy: func(a Attributes) error {
			calls++
			want := Attributes{PolicyIdentifier: policy, Sensitivity: "SECRET", Context: []string{"EXERCISE"}, Only: []string{"ALPHA"}, Releasability: []string{"FVEY"}}
			if !reflect.DeepEqual(a, want) {
				t.Fatalf("policy input = %+v, want %+v", a, want)
			}
			return rejected
		}}
		if err := profile.ValidateStructure(set); err != nil || calls != 0 {
			t.Fatalf("structural validation invoked policy or failed: %v", err)
		}
		if err := profile.Validate(set); !errors.Is(err, rejected) || calls != 1 {
			t.Fatalf("%s bypassed delegated validation: %v", policy, err)
		}
	}
	profile := Profile{ValidatePolicy: func(Attributes) error {
		t.Fatal("invalid structure reached policy validation")
		return nil
	}}
	if err := profile.Validate(makeSet(t, map[string]any{"p": "NATO", "s": "SECRET", "c": ""})); err == nil {
		t.Fatal("accepted an invalid NATO context")
	}
}

func TestCompatibility(t *testing.T) {
	legacy := makeSet(t, map[string]any{"p": "NATO", "s": "SECRET"})
	before := legacy.Repr()
	var seen Attributes
	profile := Profile{DefaultNATOContext: []string{"EXERCISE"}, ValidatePolicy: func(a Attributes) error {
		seen = a
		return nil
	}}
	if err := (Profile{}).ValidateStructure(legacy); err == nil {
		t.Fatal("missing context accepted without opt-in")
	}
	if err := profile.Validate(legacy); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(seen.Context, []string{"EXERCISE"}) || legacy.Has("c") || legacy.Repr() != before {
		t.Fatal("compatibility must supply context without rewriting identity")
	}
	for _, context := range [][]string{{"exercise"}, {"RELEASABLE"}, {"ALPHA", "BRAVO"}} {
		bad := profile
		bad.DefaultNATOContext = context
		if err := bad.Validate(legacy); err == nil {
			t.Fatalf("accepted invalid default %q", context)
		}
	}
	for key, value := range map[string]string{"c": "", "o": "ALPHA"} {
		m := legacy.Map()
		m[key] = value
		if err := profile.Validate(makeSet(t, m)); err == nil {
			t.Fatalf("compatibility bypassed rule for %s=%q", key, value)
		}
	}
	if err := profile.Validate(makeSet(t, map[string]any{"p": "USA", "s": "SECRET"})); err != nil || seen.Context != nil {
		t.Fatal("NATO default applied to a national policy")
	}
	profile.ValidatePolicy = nil
	if err := profile.Validate(legacy); !errors.Is(err, ErrPolicyRequired) {
		t.Fatal("compatibility skipped delegated policy validation")
	}
}

func TestConstruction(t *testing.T) {
	input := Attributes{
		PolicyIdentifier: "usa", Sensitivity: "secret", Releasability: []string{"fvey", "can"},
		Context: []string{"bravo", "alpha"}, Only: []string{"bravo", "alpha"},
	}
	set, err := New(input)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"p": "USA", "s": "SECRET", "r": "CAN,FVEY", "c": "ALPHA,BRAVO", "o": "ALPHA,BRAVO"}
	if !reflect.DeepEqual(set.Map(), want) || input.Releasability[0] != "fvey" || input.Context[0] != "bravo" {
		t.Fatalf("construction = %v, input = %+v", set.Map(), input)
	}
	for _, bad := range []Attributes{
		{PolicyIdentifier: "PUBLIC", Sensitivity: "UNMARKED", Releasability: []string{"fvey", "FVEY"}},
		{PolicyIdentifier: "PUBLIC", Sensitivity: "UNMARKED", Releasability: []string{"CAN,USA"}},
		{PolicyIdentifier: "NATO", Sensitivity: "SECRET", Context: []string{" EXERCISE"}},
		{PolicyIdentifier: "NATO", Sensitivity: "SECRET"},
		{PolicyIdentifier: "USA", Sensitivity: "\xff"},
	} {
		if _, err := New(bad); err == nil {
			t.Fatalf("constructor silently repaired or accepted %+v", bad)
		}
	}
}

func TestDistinctRepresentations(t *testing.T) {
	seen := map[attrset.Repr]bool{}
	for _, r := range [][]string{nil, {}, {"FVEY"}, {"AUS", "CAN", "GBR", "NZL", "USA"}} {
		set, err := New(Attributes{PolicyIdentifier: "PUBLIC", Sensitivity: "UNMARKED", Releasability: r})
		if err != nil {
			t.Fatal(err)
		}
		if seen[set.Repr()] {
			t.Fatal("absence, empty list, group or enumeration collapsed")
		}
		seen[set.Repr()] = true
	}
	upper := makeSet(t, map[string]any{"p": "PUBLIC", "s": "UNMARKED", "extension": 42})
	lower := makeSet(t, map[string]any{"p": "public", "s": "UNMARKED", "extension": 42})
	for _, set := range []attrset.Set{upper, lower} {
		before := set.Repr()
		if err := (Profile{}).Validate(set); err != nil || set.Repr() != before || !set.Has("extension") {
			t.Fatalf("validation changed identity or rejected PUBLIC: %v", err)
		}
	}
	if lower.Repr() == upper.Repr() {
		t.Fatal("permitted policy spellings collapsed")
	}
}

func FuzzValidationPreservesIdentity(f *testing.F) {
	f.Add("PUBLIC", "UNMARKED", "FVEY")
	f.Add("USA", "SECRET", "USA,CAN")
	f.Fuzz(func(t *testing.T, policy, sensitivity, release string) {
		set, err := attrset.New(map[string]any{"p": policy, "s": sensitivity, "r": release})
		if err != nil {
			return
		}
		before := set.Repr()
		err = (Profile{}).ValidateStructure(set)
		if set.Repr() != before {
			t.Fatal("validation changed identity")
		}
		if err == nil {
			decoded, err := attrset.NewFromBytes([]byte(before))
			if err != nil || decoded.Repr() != before {
				t.Fatalf("accepted Set failed deterministic round trip: %v", err)
			}
		}
	})
}
