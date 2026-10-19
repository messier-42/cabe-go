// Package acp240 provides explicitly selected construction and validation of
// [CABE-ACP240] Attribute Sets. Generic CABE operations do not invoke this package.
//
// A Profile enforces the published mapping rules. Except for PUBLIC, full
// validation also requires a caller-supplied policy validator: CABE-ACP240 does
// not enumerate national sensitivities or the additional Context/Only rules.
// Validation never repairs an Attribute Set or changes its serialized identity.
// COUNTRY is uppercase ASCII; the ABNF literals NATO and PUBLIC are matched
// case-insensitively. Their original spelling is retained during validation.
//
// This package accepts mapped attributes, not STANAG 4774 source labels. A source
// translator must separately preserve and enforce applicable restrictions,
// including restrictions outside this mapping, or fail the translation.
//
// [CABE-ACP240]: https://cabespec.org/spec/acp240/
package acp240

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/messier-42/cabe-go/attrset"
)

const (
	natoPolicy   = "NATO"
	publicPolicy = "PUBLIC"
)

// Attributes contains the five attributes defined by CABE-ACP240.
// Nil slices omit an attribute; non-nil empty slices encode an empty string.
// Each list element is one value, not a comma-separated list.
type Attributes struct {
	// PolicyIdentifier (p) is the governing security policy understood by the
	// encapsulator, not the identity of the encapsulator or originator. It
	// supplies the policy context for interpreting s, r, c and o.
	PolicyIdentifier string
	Sensitivity      string   // s
	Releasability    []string // r; group identifiers are not expanded into countries
	Context          []string // c
	Only             []string // o
}

// Profile configures CABE-ACP240 validation. Its zero value fully supports PUBLIC.
// Configure ValidatePolicy to complete checks delegated to other policies.
type Profile struct {
	// ValidatePolicy checks the governing policy's additional requirements,
	// including national sensitivities and Context/Only presence and values.
	// It must reject policies it does not support. It receives structurally valid mapped
	// attributes after the published rules have passed, with any configured
	// compatibility context supplied in Context. It must not change its input.
	// PolicyIdentifier retains the original spelling, including the permitted
	// ASCII case variants of NATO and PUBLIC.
	// Nil is sufficient only for PUBLIC. This is not a Key Service authorization
	// check; callers remain responsible for authorization and other attributes.
	ValidatePolicy func(Attributes) error

	// DefaultNATOContext explicitly enables the published compatibility exception
	// for an existing NATO Attribute Set with no c. It must contain one canonical
	// context value. It is used for validation only, never inserted into the Set.
	// New still requires an explicit c. Nil disables the exception.
	DefaultNATOContext []string
}

// ErrPolicyRequired indicates that the published rules passed but additional
// policy-specific validation is required before the Set can be accepted.
var ErrPolicyRequired = errors.New("acp240: governing policy validation is required")

// ValidationError identifies a mapped attribute that violates a published rule.
type ValidationError struct {
	Attribute string
	Reason    string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("acp240: %s: %s", e.Attribute, e.Reason)
}

func invalid(attribute, reason string) error {
	return &ValidationError{Attribute: attribute, Reason: reason}
}

// New constructs a canonical Set, uppercasing values and sorting lists before
// checking the published mapping rules. Construction does not establish complete
// policy conformance; use Profile.Validate to check delegated policy rules.
// New does not trim whitespace, remove duplicates, expand groups,
// or infer a missing Context. Neither input slices nor their ordering are changed.
// Only the five mapped attributes can be constructed through this function.
func New(a Attributes) (attrset.Set, error) {
	if !utf8.ValidString(a.Sensitivity) {
		return attrset.Set{}, invalid("s", "must contain valid UTF-8")
	}
	m := map[string]any{
		"p": asciiUpper(a.PolicyIdentifier),
		"s": strings.ToUpper(a.Sensitivity),
	}
	for _, field := range []struct {
		name   string
		values []string
	}{
		{"r", a.Releasability}, {"c", a.Context}, {"o", a.Only},
	} {
		if field.values == nil {
			continue
		}
		values := slices.Clone(field.values)
		for i, value := range values {
			values[i] = asciiUpper(value)
			if !validItem(values[i], field.name == "r") {
				return attrset.Set{}, invalid(field.name, fmt.Sprintf("invalid list item %q", value))
			}
		}
		slices.Sort(values)
		m[field.name] = strings.Join(values, ",")
	}
	set, err := attrset.New(m)
	if err != nil {
		return attrset.Set{}, err
	}
	// Compatibility permits processing old Sets, not constructing new ones.
	if err := (Profile{}).ValidateStructure(set); err != nil {
		return attrset.Set{}, err
	}
	return set, nil
}

// Validate checks the published mapping rules and additional governing policy
// rules, rejecting noncanonical values without normalizing or mutating the Set.
// Attributes outside p, s, r, c and o are retained and are not validated here;
// CABE-ACP240 does not define a closed set of permitted attribute names.
// For serialized input, first use attrset.NewFromBytes to check CBOR canonicality.
func (p Profile) Validate(set attrset.Set) error {
	a, err := p.checkRules(set)
	if err != nil {
		return err
	}
	if p.ValidatePolicy != nil {
		if err := p.ValidatePolicy(a); err != nil {
			return fmt.Errorf("acp240: policy %q: %w", a.PolicyIdentifier, err)
		}
	} else if asciiUpper(a.PolicyIdentifier) != publicPolicy {
		return fmt.Errorf("%w for %q; configure Profile.ValidatePolicy for its delegated rules", ErrPolicyRequired, a.PolicyIdentifier)
	}
	return nil
}

// ValidateStructure checks all rules stated explicitly in CABE-ACP240, including
// its NATO/PUBLIC constraints, without calling ValidatePolicy.
// Success alone does not establish policy conformance for NATO or
// national policies. Use Validate before accepting a Set for those policies.
func (p Profile) ValidateStructure(set attrset.Set) error {
	_, err := p.checkRules(set)
	return err
}

func (p Profile) checkRules(set attrset.Set) (Attributes, error) {
	var a Attributes
	policy, err := requiredString(set, "p")
	if err != nil {
		return a, err
	}
	// ABNF quoted literals are ASCII case-insensitive (RFC 5234 section 2.3).
	// COUNTRY instead uses the explicit range %x41-5A. This comparison selects
	// the applicable rules; it does not rewrite the policy identifier.
	policyKind := asciiUpper(policy)
	if policyKind != natoPolicy && policyKind != publicPolicy && !(len(policy) == 3 && upperLetters(policy)) {
		return a, invalid("p", "must match NATO or PUBLIC (ASCII case-insensitive), or three uppercase ASCII letters")
	}
	a.PolicyIdentifier = policy
	a.Sensitivity, err = requiredString(set, "s")
	if err != nil {
		return a, err
	}
	if strings.ContainsFunc(a.Sensitivity, func(r rune) bool { return unicode.IsLower(r) || unicode.IsTitle(r) }) {
		return a, invalid("s", "must be uppercase")
	}
	switch policyKind {
	case natoPolicy:
		if !slices.Contains([]string{"UNCLASSIFIED", "RESTRICTED", "CONFIDENTIAL", "SECRET", "TOP SECRET"}, a.Sensitivity) {
			return a, invalid("s", "NATO requires UNCLASSIFIED, RESTRICTED, CONFIDENTIAL, SECRET, or TOP SECRET")
		}
	case publicPolicy:
		if a.Sensitivity != "UNMARKED" {
			return a, invalid("s", "PUBLIC requires UNMARKED")
		}
	}
	for _, field := range []struct {
		name string
		dest *[]string
	}{
		{"r", &a.Releasability}, {"c", &a.Context}, {"o", &a.Only},
	} {
		if set.Has(field.name) {
			value, err := requiredString(set, field.name)
			if err != nil {
				return a, err
			}
			*field.dest, err = parseList(field.name, value)
			if err != nil {
				return a, err
			}
		}
	}
	if policyKind == publicPolicy {
		if a.Context != nil {
			return a, invalid("c", "must not be present under PUBLIC")
		}
		if a.Only != nil {
			return a, invalid("o", "must not be present under PUBLIC")
		}
	}
	if a.Only != nil && a.Context == nil {
		return a, invalid("o", "must not be present unless c is present")
	}
	if policyKind == natoPolicy {
		if a.Context == nil && p.DefaultNATOContext != nil {
			a.Context = slices.Clone(p.DefaultNATOContext)
		}
		if len(a.Context) != 1 {
			return a, invalid("c", "NATO requires exactly one context value; missing c needs an explicit compatibility default when validating an existing Set")
		}
		if !validItem(a.Context[0], false) || a.Context[0] == "RELEASABLE" {
			return a, invalid("c", "NATO requires a canonical context other than RELEASABLE; releasability is represented by non-empty r")
		}
	}
	return a, nil
}

func requiredString(set attrset.Set, name string) (string, error) {
	v, present := set.Get(name)
	if !present {
		return "", invalid(name, "required attribute is missing")
	}
	s, ok := v.(string)
	if !ok {
		return "", invalid(name, "must be a string")
	}
	if !utf8.ValidString(s) {
		return "", invalid(name, "must contain valid UTF-8")
	}
	return s, nil
}

func parseList(name, value string) ([]string, error) {
	if value == "" {
		if name == "o" {
			// The explicit non-empty requirement takes precedence over the
			// optional brackets in the specification's ONLY production.
			return nil, invalid(name, "must be non-empty when present")
		}
		return []string{}, nil
	}
	items := strings.Split(value, ",")
	for i, item := range items {
		if !validItem(item, name == "r") {
			return nil, invalid(name, fmt.Sprintf("invalid list item %q; use uppercase ASCII letters and permitted spaces", item))
		}
		if i > 0 && items[i-1] >= item {
			return nil, invalid(name, "values must be in ascending lexicographic order without duplicates")
		}
	}
	return items, nil
}

func upperLetters(value string) bool {
	for i := range len(value) {
		if value[i] < 'A' || value[i] > 'Z' {
			return false
		}
	}
	return value != ""
}

func validItem(value string, group bool) bool {
	if group {
		// SPECIAL_GROUP permits any non-empty sequence of UPPER_ALPHA / SP.
		// Do not import the stricter C_VALUE/O_VALUE word spacing rules.
		for i := range len(value) {
			if value[i] != ' ' && (value[i] < 'A' || value[i] > 'Z') {
				return false
			}
		}
		return value != ""
	}
	for word := range strings.SplitSeq(value, " ") {
		if !upperLetters(word) {
			return false
		}
	}
	return true
}

func asciiUpper(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r - ('a' - 'A')
		}
		return r
	}, value)
}
