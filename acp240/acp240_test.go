//nolint:goconst // Literal test inputs make the grammar and case distinctions visible.
package acp240

import (
	"errors"
	"maps"
	"reflect"
	"strings"
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
	// EXERCISE is test data, not a prescribed NATO context.
	nato := map[string]any{"p": "NATO", "s": "SECRET", "c": "EXERCISE"}
	tests := []struct {
		name  string
		base  map[string]any
		key   string
		value any    // nil removes key
		want  string // attribute that must fail; empty means structural success
	}{
		{"NATO", nato, "", nil, ""},
		{"NATO unclassified", nato, "s", "UNCLASSIFIED", ""},
		{"NATO restricted", nato, "s", "RESTRICTED", ""},
		{"NATO confidential", nato, "s", "CONFIDENTIAL", ""},
		{"NATO top secret", nato, "s", "TOP SECRET", ""},
		{"missing policy", nato, "p", nil, "p"},
		{"policy type", nato, "p", 1, "p"},
		{"policy length", nato, "p", "US", "p"},
		{"country lowercase", nato, "p", "usa", "p"},
		{"country mixed case", nato, "p", "UsA", "p"},
		{"country digits", nato, "p", "US1", "p"},
		{"policy non ASCII", nato, "p", "publıc", "p"},
		{"NATO literal case", nato, "p", "nAtO", ""},
		{"missing sensitivity", nato, "s", nil, "s"},
		{"sensitivity type", nato, "s", true, "s"},
		{"sensitivity lowercase", nato, "s", "secret", "s"},
		{"NATO unknown sensitivity", nato, "s", "UNMARKED", "s"},
		{"NATO empty sensitivity", nato, "s", "", "s"},
		{"NATO missing context", nato, "c", nil, "c"},
		{"NATO empty context", nato, "c", "", "c"},
		{"NATO multiple contexts", nato, "c", "ALPHA,BRAVO", "c"},
		{"NATO explicit releasable", nato, "c", "RELEASABLE", "c"},
		{"NATO releasable mixed case", nato, "c", "Releasable", "c"},
		{"NATO releasability", nato, "r", "AUS,CAN,FVEY", ""},
		{"NATO only", nato, "o", "ALPHA,BRAVO", ""},
		{"empty releasability", nato, "r", "", ""},
		{"group identifier", nato, "r", "FVEY", ""},
		{"groups and countries", nato, "r", "CAN,FVEY,USA", ""},
		{"special group spacing grammar", nato, "r", "  GROUP  NAME ", ""},
		{"special group spaces grammar", nato, "r", " ", ""},
		{"releasability order", nato, "r", "USA,CAN", "r"},
		{"releasability duplicate", nato, "r", "FVEY,FVEY", "r"},
		{"releasability lowercase", nato, "r", "fvey", "r"},
		{"releasability type", nato, "r", []string{"FVEY"}, "r"},
		{"releasability punctuation", nato, "r", "FVEY-PLUS", "r"},
		{"releasability trailing comma", nato, "r", "FVEY,", "r"},
		{"releasability empty item", nato, "r", "CAN,,USA", "r"},
		{"releasability non ASCII", nato, "r", "FVEÝ", "r"},
		{"context type", nato, "c", []string{"EXERCISE"}, "c"},
		{"context lowercase", nato, "c", "exercise", "c"},
		{"context leading space", nato, "c", " EXERCISE", "c"},
		{"context trailing space", nato, "c", "EXERCISE ", "c"},
		{"context doubled space", nato, "c", "TEST  CONTEXT", "c"},
		{"context words", nato, "c", "TEST CONTEXT", ""},
		{"context tab", nato, "c", "TEST\tCONTEXT", "c"},
		{"context trailing comma", nato, "c", "EXERCISE,", "c"},
		{"only empty despite ABNF", nato, "o", "", "o"},
		{"only type", nato, "o", false, "o"},
		{"only lowercase", nato, "o", "alpha", "o"},
		{"only order", nato, "o", "BRAVO,ALPHA", "o"},
		{"only duplicates", nato, "o", "ALPHA,ALPHA", "o"},
		{"only trailing comma", nato, "o", "ALPHA,", "o"},
		{"only extra space", nato, "o", "ALPHA  BRAVO", "o"},
		{"only words", nato, "o", "ALPHA BRAVO", ""},
		{"public", map[string]any{"p": "PUBLIC", "s": "UNMARKED"}, "", nil, ""},
		{"public literal case", map[string]any{"p": "pUbLiC", "s": "UNMARKED"}, "", nil, ""},
		{"public lowercase sensitivity", map[string]any{"p": "PUBLIC", "s": "unmarked"}, "", nil, "s"},
		{"public wrong sensitivity", map[string]any{"p": "PUBLIC", "s": "SECRET"}, "", nil, "s"},
		{"public context", map[string]any{"p": "PUBLIC", "s": "UNMARKED", "c": ""}, "", nil, "c"},
		{"public only", map[string]any{"p": "PUBLIC", "s": "UNMARKED", "o": "ALPHA"}, "", nil, "o"},
		{"only requires actual context", map[string]any{"p": "USA", "s": "SECRET", "o": "ALPHA"}, "", nil, "o"},
		{"national absent context", map[string]any{"p": "USA", "s": "SECRET"}, "", nil, ""},
		{"national empty context", map[string]any{"p": "USA", "s": "SECRET", "c": ""}, "", nil, ""},
		{"national multiple contexts", map[string]any{"p": "USA", "s": "SECRET", "c": "ALPHA,BRAVO"}, "", nil, ""},
		{"national context duplicates", map[string]any{"p": "USA", "s": "SECRET", "c": "ALPHA,ALPHA"}, "", nil, "c"},
		{"national context order", map[string]any{"p": "USA", "s": "SECRET", "c": "BRAVO,ALPHA"}, "", nil, "c"},
		{"national RELEASABLE", map[string]any{"p": "USA", "s": "SECRET", "c": "RELEASABLE"}, "", nil, ""},
		{"no invented sensitivity alphabet", map[string]any{"p": "ZZZ", "s": "LEVEL_1"}, "", nil, ""},
		{"national uppercase Unicode", map[string]any{"p": "ZZZ", "s": "ÉLEVÉ"}, "", nil, ""},
		{"national lowercase Unicode without simple uppercase", map[string]any{"p": "ZZZ", "s": "ß"}, "", nil, "s"},
		{"national invalid UTF-8", map[string]any{"p": "ZZZ", "s": "\xff"}, "", nil, "s"},
		{"no invented country registry", map[string]any{"p": "ZZZ", "s": "TEST"}, "", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := maps.Clone(tt.base)
			if tt.key != "" {
				if tt.value == nil {
					delete(m, tt.key)
				} else {
					m[tt.key] = tt.value
				}
			}
			set := makeSet(t, m)
			before := set.Repr()
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
			if set.Repr() != before || !reflect.DeepEqual(set.Map(), m) {
				t.Fatal("validation changed the Attribute Set")
			}
		})
	}
}

func TestDelegatedPolicyValidation(t *testing.T) {
	for _, policy := range []string{"NATO", "USA", "ZZZ"} {
		set := makeSet(t, map[string]any{"p": policy, "s": "SECRET", "c": "EXERCISE"})
		if err := (Profile{}).ValidateStructure(set); err != nil {
			t.Fatal(err)
		}
		if err := (Profile{}).Validate(set); !errors.Is(err, ErrPolicyRequired) {
			t.Fatalf("%s: got %v, want insufficient policy information", policy, err)
		}
	}
	for _, policy := range []string{"PUBLIC", "public", "pUbLiC"} {
		set := makeSet(t, map[string]any{"p": policy, "s": "UNMARKED"})
		if err := (Profile{}).Validate(set); err != nil {
			t.Fatal(err)
		}
	}

	// These are deliberately fixture rules, not invented national/NATO policy.
	rejected := errors.New("unsupported policy or disallowed test combination")
	calls := 0
	profile := Profile{ValidatePolicy: func(a Attributes) error {
		calls++
		if a.PolicyIdentifier != "ZZZ" || a.Sensitivity != "TEST" ||
			!reflect.DeepEqual(a.Context, []string{"ALPHA", "BRAVO"}) ||
			!reflect.DeepEqual(a.Only, []string{"ALPHA"}) {
			return rejected
		}
		return nil
	}}
	set := makeSet(t, map[string]any{"p": "ZZZ", "s": "TEST", "c": "ALPHA,BRAVO", "o": "ALPHA"})
	if err := profile.Validate(set); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct{ key, value string }{
		{"p", "USA"}, {"s", "SECRET"}, {"c", "BRAVO"}, {"o", "BRAVO"},
	} {
		m := set.Map()
		m[change.key] = change.value
		if err := profile.Validate(makeSet(t, m)); !errors.Is(err, rejected) {
			t.Fatalf("policy failure was lost: %v", err)
		}
	}
	before := calls
	bad := makeSet(t, map[string]any{"p": "NATO", "s": "SECRET", "c": "ALPHA,BRAVO"})
	if err := profile.Validate(bad); err == nil || calls != before {
		t.Fatal("callback ran before explicit NATO rules")
	}
	if err := profile.ValidateStructure(set); err != nil || calls != before {
		t.Fatal("structural validation invoked the policy callback")
	}
}

func TestCompatibility(t *testing.T) {
	legacy := makeSet(t, map[string]any{"p": "NATO", "s": "SECRET", "r": "FVEY"})
	before := legacy.Repr()
	var seen Attributes
	profile := Profile{
		DefaultNATOContext: []string{"EXERCISE"},
		ValidatePolicy: func(a Attributes) error {
			seen = a
			return nil
		},
	}
	if err := (Profile{}).ValidateStructure(legacy); err == nil {
		t.Fatal("missing context accepted without explicit opt-in")
	}
	if err := profile.Validate(legacy); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(seen.Context, []string{"EXERCISE"}) || legacy.Has("c") || legacy.Repr() != before {
		t.Fatal("compatibility failed to supply context without rewriting identity")
	}
	for _, context := range [][]string{{}, {""}, {"exercise"}, {"RELEASABLE"}, {"ALPHA", "BRAVO"}, {"ALPHA,BRAVO"}} {
		badProfile := profile
		badProfile.DefaultNATOContext = context
		if err := badProfile.Validate(legacy); err == nil {
			t.Fatalf("accepted invalid compatibility default %q", context)
		}
	}
	for _, change := range []struct{ key, value string }{{"c", ""}, {"c", "exercise"}, {"c", "ALPHA,BRAVO"}, {"o", "ALPHA"}} {
		m := legacy.Map()
		m[change.key] = change.value
		if err := profile.Validate(makeSet(t, m)); err == nil {
			t.Fatalf("compatibility bypassed rule for %s=%q", change.key, change.value)
		}
	}
	m := legacy.Map()
	m["p"] = "USA"
	seen = Attributes{}
	if err := profile.Validate(makeSet(t, m)); err != nil || seen.Context != nil {
		t.Fatal("NATO default applied to a national policy")
	}
	if _, err := New(Attributes{PolicyIdentifier: "NATO", Sensitivity: "SECRET"}); err == nil {
		t.Fatal("constructor omitted required NATO context")
	}
	profile.ValidatePolicy = nil
	if err := profile.Validate(legacy); !errors.Is(err, ErrPolicyRequired) {
		t.Fatal("compatibility skipped delegated policy validation")
	}
}

func TestPolicyCaseDoesNotBypassChecks(t *testing.T) {
	for _, policy := range []string{"NATO", "nato", "nAtO"} {
		set := makeSet(t, map[string]any{"p": policy, "s": "SECRET", "c": "EXERCISE"})
		policyError := errors.New("context not permitted by governing policy")
		profile := Profile{ValidatePolicy: func(a Attributes) error {
			if a.PolicyIdentifier != policy {
				t.Fatal("callback did not receive the original policy spelling")
			}
			return policyError
		}}
		if err := profile.Validate(set); !errors.Is(err, policyError) {
			t.Fatalf("%s bypassed delegated checks: %v", policy, err)
		}
		if err := (Profile{}).Validate(set); !errors.Is(err, ErrPolicyRequired) {
			t.Fatalf("%s reported conformance without policy information: %v", policy, err)
		}
	}
}

func TestConstructionAndIdentity(t *testing.T) {
	input := Attributes{
		PolicyIdentifier: "usa", Sensitivity: "test",
		Releasability: []string{"usa", "fvey", "can"},
		Context:       []string{"bravo", "alpha"}, Only: []string{"bravo", "alpha"},
	}
	set, err := New(input)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"p": "USA", "s": "TEST", "r": "CAN,FVEY,USA", "c": "ALPHA,BRAVO", "o": "ALPHA,BRAVO"}
	if !reflect.DeepEqual(set.Map(), want) || input.Releasability[0] != "usa" || input.Context[0] != "bravo" {
		t.Fatalf("construction = %v, input = %+v", set.Map(), input)
	}
	if err := (Profile{}).Validate(set); !errors.Is(err, ErrPolicyRequired) {
		t.Fatal("construction was mistaken for complete policy conformance")
	}
	decoded, err := attrset.NewFromBytes([]byte(set.Repr()))
	if err != nil || decoded.Repr() != set.Repr() {
		t.Fatalf("identity lost on CBOR round trip: %v", err)
	}
	if err := (Profile{}).ValidateStructure(decoded); err != nil || decoded.Repr() != set.Repr() {
		t.Fatalf("identity lost on validation: %v", err)
	}
	for _, field := range []string{"r", "c", "o"} {
		for _, values := range [][]string{{"alpha", "ALPHA"}, {"ALPHA,BRAVO"}, {""}} {
			a := Attributes{PolicyIdentifier: "USA", Sensitivity: "TEST", Context: []string{"ALPHA"}}
			switch field {
			case "r":
				a.Releasability = values
			case "c":
				a.Context = values
			case "o":
				a.Only = values
			}
			if _, err := New(a); err == nil {
				t.Fatalf("constructor accepted %s=%q", field, values)
			}
		}
	}
	if _, err := New(Attributes{PolicyIdentifier: "NATO", Sensitivity: "SECRET", Context: []string{" EXERCISE"}}); err == nil {
		t.Fatal("constructor silently trimmed context")
	}
	if _, err := New(Attributes{PolicyIdentifier: "ZZZ", Sensitivity: "\xff"}); err == nil {
		t.Fatal("constructor silently repaired invalid UTF-8")
	}
}

func TestDistinctRepresentations(t *testing.T) {
	representations := map[attrset.Repr]bool{}
	for _, r := range [][]string{nil, {}, {"FVEY"}, {"AUS", "CAN", "GBR", "NZL", "USA"}} {
		set, err := New(Attributes{PolicyIdentifier: "PUBLIC", Sensitivity: "UNMARKED", Releasability: r})
		if err != nil {
			t.Fatal(err)
		}
		if representations[set.Repr()] {
			t.Fatal("absence, empty list, group or enumeration collapsed to the same Set")
		}
		representations[set.Repr()] = true
		if err := (Profile{}).Validate(set); err != nil {
			t.Fatal(err)
		}
	}
	upper := makeSet(t, map[string]any{"p": "PUBLIC", "s": "UNMARKED", "extension": 42})
	lower := makeSet(t, map[string]any{"p": "public", "s": "UNMARKED", "extension": 42})
	for _, set := range []attrset.Set{upper, lower} {
		before := set.Repr()
		if err := (Profile{}).Validate(set); err != nil || set.Repr() != before || !set.Has("extension") {
			t.Fatalf("validation rewrote permitted spelling or other attributes: %v", err)
		}
	}
	if lower.Repr() == upper.Repr() {
		t.Fatal("permitted policy spellings collapsed")
	}
}

func FuzzValidationPreservesIdentity(f *testing.F) {
	f.Add("PUBLIC", "UNMARKED", "FVEY")
	f.Add("NATO", "SECRET", "USA,CAN")
	f.Add("USA", "TEST", "")
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
				t.Fatal("valid Set failed deterministic round trip")
			}
			if strings.ToUpper(sensitivity) != sensitivity {
				t.Fatal("accepted lowercase sensitivity")
			}
		}
	})
}
