//nolint:goconst // Keep complete command-line inputs visible in the test table.
package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		stdin string
		scope string
		want  string
	}{
		{"explicit profile", nil, "", "", "select --profile acp240"},
		{"input required", []string{"--profile", "acp240"}, "", "", "provide either"},
		{"exclusive inputs", []string{"--profile", "acp240", "--in", "-", "-A", "p=str:PUBLIC"}, "", "", "not both"},
		{"full", []string{"--profile", "acp240", "-A", "p=str:PUBLIC", "-A", "s=str:UNMARKED"}, "", "full", ""},
		{"incomplete", []string{"--profile", "acp240", "-A", "p=str:NATO", "-A", "s=str:SECRET", "-A", "c=str:EXERCISE"}, "", "", "governing policy validation is required"},
		{"structural", []string{"--profile", "acp240", "--structural-only", "-A", "p=str:NATO", "-A", "s=str:SECRET", "-A", "c=str:EXERCISE"}, "", "structural-only", ""},
		{"compatibility flag", []string{"--profile", "acp240", "--structural-only", "--nato-default-context", "EXERCISE", "-A", "p=str:NATO", "-A", "s=str:SECRET"}, "", "structural-only", ""},
		{"invalid value", []string{"--profile", "acp240", "--structural-only", "-A", "p=str:PUBLIC", "-A", "s=str:unmarked"}, "", "", "s: must be uppercase"},
		{"CBOR", []string{"--profile", "acp240", "--in", "-"}, "\xa2\x61p\x66PUBLIC\x61s\x68UNMARKED", "full", ""},
		{"noncanonical CBOR", []string{"--profile", "acp240", "--in", "-"}, "\xa2\x61s\x68UNMARKED\x61p\x66PUBLIC", "", "not in deterministic form"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exit, stdout, stderr := runArgs(t, tt.stdin, append([]string{"validate", "-J"}, tt.args...)...)
			if tt.want != "" {
				if exit == 0 || !strings.Contains(stderr, tt.want) || stdout != "" {
					t.Fatalf("exit=%d, out=%q, err=%q; want %q", exit, stdout, stderr, tt.want)
				}
				return
			}
			if exit != 0 {
				t.Fatalf("exit=%d: %s", exit, stderr)
			}
			var result map[string]any
			if err := json.Unmarshal([]byte(stdout), &result); err != nil || result["scope"] != tt.scope {
				t.Fatalf("output=%s, err=%v", stdout, err)
			}
		})
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
