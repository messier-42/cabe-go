//nolint:goconst // Keep complete command-line inputs visible in the test table.
package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/messier-42/cabe-go/attrset"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		want  string
		scope string
	}{
		{"public", []string{"-A", "p=str:PUBLIC", "-A", "s=str:UNMARKED"}, "", "full"},
		{"public mixed case", []string{"-A", "p=str:pUbLiC", "-A", "s=str:UNMARKED"}, "", "full"},
		{"public constraints despite case", []string{"-A", "p=str:public", "-A", "s=str:SECRET"}, "PUBLIC requires UNMARKED", ""},
		{"no input", nil, "provide either", ""},
		{"mixed inputs", []string{"--in", "-", "-A", "p=str:PUBLIC"}, "not both", ""},
		{"missing sensitivity", []string{"-A", "p=str:PUBLIC"}, "s: required", ""},
		{"duplicate name", []string{"-A", "p=str:PUBLIC", "-A", "p=str:PUBLIC"}, "more than once", ""},
		{"non string", []string{"-A", "p=int:1"}, "p: must be a string", ""},
		{"NATO incomplete", []string{"-A", "p=str:NATO", "-A", "s=str:SECRET", "-A", "c=str:EXERCISE"}, "--structural-only", ""},
		{"NATO lowercase incomplete", []string{"-A", "p=str:nato", "-A", "s=str:SECRET", "-A", "c=str:EXERCISE"}, "governing policy validation is required", ""},
		{"NATO structural", []string{"--structural-only", "-A", "p=str:NATO", "-A", "s=str:SECRET", "-A", "c=str:EXERCISE"}, "", "structural-only"},
		{"national incomplete", []string{"-A", "p=str:USA", "-A", "s=str:SECRET"}, "governing policy validation is required", ""},
		{"national structural", []string{"--structural-only", "-A", "p=str:USA", "-A", "s=str:SECRET"}, "", "structural-only"},
		{"NATO missing context", []string{"--structural-only", "-A", "p=str:NATO", "-A", "s=str:SECRET"}, "exactly one context", ""},
		{"NATO cardinality despite case", []string{"--structural-only", "-A", "p=str:nAtO", "-A", "s=str:SECRET", "-A", "c=str:ALPHA,BRAVO"}, "exactly one context", ""},
		{"compatibility", []string{"--structural-only", "--nato-default-context", "EXERCISE", "-A", "p=str:NATO", "-A", "s=str:SECRET"}, "", "structural-only"},
		{"compatibility still incomplete", []string{"--nato-default-context", "EXERCISE", "-A", "p=str:NATO", "-A", "s=str:SECRET"}, "governing policy validation is required", ""},
		{"empty ONLY", []string{"--structural-only", "-A", "p=str:NATO", "-A", "s=str:SECRET", "-A", "c=str:EXERCISE", "-A", "o=str:"}, "o: must be non-empty", ""},
		{"no sorting", []string{"-A", "p=str:PUBLIC", "-A", "s=str:UNMARKED", "-A", "r=str:USA,CAN"}, "ascending lexicographic", ""},
		{"no uppercasing", []string{"-A", "p=str:PUBLIC", "-A", "s=str:unmarked"}, "s: must be uppercase", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"validate", "--profile", "acp240", "-J"}, tt.args...)
			exit, stdout, stderr := runArgs(t, "", args...)
			if tt.want != "" {
				if exit == 0 || !strings.Contains(stderr, tt.want) || stdout != "" {
					t.Fatalf("exit=%d, stdout=%q, stderr=%q; want %q", exit, stdout, stderr, tt.want)
				}
				return
			}
			if exit != 0 {
				t.Fatalf("exit=%d: %s", exit, stderr)
			}
			var result struct {
				Scope        string         `json:"scope"`
				AttributeSet map[string]any `json:"attributeSet"`
			}
			if err := json.Unmarshal([]byte(stdout), &result); err != nil || result.Scope != tt.scope {
				t.Fatalf("output=%s, err=%v", stdout, err)
			}
			if tt.name == "compatibility" && result.AttributeSet["c"] != nil {
				t.Fatal("compatibility rewrote the Attribute Set")
			}
			if tt.name == "public mixed case" && result.AttributeSet["p"] != "pUbLiC" {
				t.Fatal("validation rewrote policy spelling")
			}
		})
	}
}

func TestValidateCBOR(t *testing.T) {
	set, err := attrset.New(map[string]any{"p": "PUBLIC", "s": "UNMARKED"})
	if err != nil {
		t.Fatal(err)
	}
	exit, stdout, stderr := runArgs(t, string(set.Repr()), "validate", "--profile", "acp240", "--in", "-")
	if exit != 0 || !strings.Contains(stdout, "scope: full") {
		t.Fatalf("exit=%d, stdout=%q, stderr=%q", exit, stdout, stderr)
	}
	for _, data := range []string{
		"",
		"\xa2\x61s\x68UNMARKED\x61p\x66PUBLIC", // Non-deterministic map order.
		"\xa2\x61p\x66PUBLIC\x61p\x66PUBLIC",   // Duplicate map key.
		"\xbf\x61p\x66PUBLIC\x61s\x68UNMARKED\xff", // Indefinite-length map.
	} {
		exit, stdout, stderr := runArgs(t, data, "validate", "--profile", "acp240", "--in", "-")
		if exit == 0 || stdout != "" || !strings.Contains(stderr, "read Attribute Set") {
			t.Fatalf("accepted invalid CBOR %x: exit=%d, out=%q, err=%q", data, exit, stdout, stderr)
		}
	}
	for _, args := range [][]string{{"validate"}, {"validate", "--profile", "other"}} {
		exit, _, stderr := runArgs(t, "", args...)
		if exit == 0 || !strings.Contains(stderr, "--profile acp240") {
			t.Fatalf("profile was not explicitly selected: exit=%d, err=%q", exit, stderr)
		}
	}
}

func TestEncapDoesNotSelectACP240(t *testing.T) {
	server := stubKeyServer(t)
	// These values violate CABE-ACP240 but remain valid generic CABE attributes.
	exit, envelope, stderr := runArgs(t, "generic payload",
		"--base-url", server.URL+"/ckap/", "encap",
		"-A", "p=str:custom-policy", "-A", "s=str:lowercase", "-A", "c=int:7")
	if exit != 0 || envelope == "" {
		t.Fatalf("generic encap changed: exit=%d, err=%q", exit, stderr)
	}
}
