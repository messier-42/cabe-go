package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

const testStructuredString = "two"

func TestParseAttrSpec(t *testing.T) {
	const urgentAttribute = "urgent"
	cases := []struct {
		in     string
		key    string
		value  any
		errMsg string // substring that must appear in the error (empty = expect success)
	}{
		{in: "level=str:secret", key: "level", value: "secret"},
		{in: "level=string:secret", key: "level", value: "secret"},
		{in: "tier=int:42", key: "tier", value: int64(42)},
		{in: "neg=int:-7", key: "neg", value: int64(-7)},
		{in: "urgent=bool:true", key: urgentAttribute, value: true},
		{in: "urgent=bool:TRUE", key: urgentAttribute, value: true},
		{in: "urgent=bool:false", key: urgentAttribute, value: false},
		{in: "empty=str:", key: "empty", value: ""},
		{in: "with-hyphen=str:x", key: "with-hyphen", value: "x"},
		// value contains a colon — we split only on the first colon after =
		{in: "note=str:hello:world", key: "note", value: "hello:world"},

		{in: "nokey", errMsg: "missing '='"},
		{in: "=str:v", errMsg: "missing '='"},
		{in: "key=justvalue", errMsg: "missing ':' after type"},
		{in: "key=float:1.0", errMsg: "unknown type"},
		{in: "key=int:notanumber", errMsg: "invalid int"},
		{in: "key=bool:yes", errMsg: "invalid bool"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			k, v, err := parseAttrSpec(c.in)
			if c.errMsg != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", c.errMsg)
				}
				if !strings.Contains(err.Error(), c.errMsg) {
					t.Fatalf("error %q does not contain %q", err.Error(), c.errMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if k != c.key {
				t.Errorf("key = %q, want %q", k, c.key)
			}
			if v != c.value {
				t.Errorf("value = %#v (%T), want %#v (%T)", v, v, c.value, c.value)
			}
		})
	}
}

func TestBuildAttributeSetRejectsDuplicates(t *testing.T) {
	_, err := buildAttributeSet([]string{"k=str:a", "k=str:b"})
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("expected duplicate-key error, got %v", err)
	}
}

func TestBuildAttributeSetValidatesKeys(t *testing.T) {
	// attrset.New rejects invalid names; our wrapper should propagate.
	if _, err := buildAttributeSet([]string{"1bad=str:x"}); err == nil {
		t.Fatal("expected error for invalid attribute name")
	}
}

func TestBuildAttributeSetEmpty(t *testing.T) {
	s, err := buildAttributeSet(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.Len() != 0 {
		t.Fatalf("Len() = %d, want 0", s.Len())
	}
}

func TestBindEnvPrecedence(t *testing.T) {
	// Flag explicitly set on the command line always wins.
	t.Setenv("TEST_FOO", "from-env")
	cmd := &cobra.Command{Use: "x"}
	var v string
	cmd.PersistentFlags().StringVar(&v, "foo", "default", "")
	if err := cmd.PersistentFlags().Set("foo", "from-flag"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	bindEnv(cmd, "foo", "TEST_FOO")
	if v != "from-flag" {
		t.Fatalf("flag > env failed: got %q, want %q", v, "from-flag")
	}

	// Env wins over default when flag unset.
	cmd2 := &cobra.Command{Use: "x"}
	var v2 string
	cmd2.PersistentFlags().StringVar(&v2, "foo", "default", "")
	bindEnv(cmd2, "foo", "TEST_FOO")
	if v2 != "from-env" {
		t.Fatalf("env > default failed: got %q, want %q", v2, "from-env")
	}

	// Unset env means default stands.
	t.Setenv("TEST_FOO", "")
	cmd3 := &cobra.Command{Use: "x"}
	var v3 string
	cmd3.PersistentFlags().StringVar(&v3, "foo", "default", "")
	bindEnv(cmd3, "foo", "TEST_FOO")
	if v3 != "default" {
		t.Fatalf("unset env: got %q, want %q", v3, "default")
	}
}

func TestWriteStructuredYAML(t *testing.T) {
	var buf bytes.Buffer
	if err := writeStructured(&buf, map[string]any{"a": 1, "b": testStructuredString}, false); err != nil {
		t.Fatalf("writeStructured() error = %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "---\n") {
		t.Fatalf("YAML output did not start with document marker: %q", out)
	}
	if !strings.Contains(out, "a: 1") || !strings.Contains(out, "b: two") {
		t.Fatalf("YAML output missing expected fields: %q", out)
	}
}

func TestWriteStructuredJSON(t *testing.T) {
	var buf bytes.Buffer
	v := map[string]any{"a": 1, "b": testStructuredString}
	if err := writeStructured(&buf, v, true); err != nil {
		t.Fatalf("writeStructured() error = %v", err)
	}
	// Parse it back to verify it's valid JSON with the expected fields.
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, buf.String())
	}
	if got["b"] != testStructuredString {
		t.Fatalf("JSON output = %v, want b=two", got)
	}
}

func TestBase64URL(t *testing.T) {
	got := base64URL([]byte{0x00, 0xff, 0x10, 0x20, 0x30})
	// Raw (unpadded) base64url of these bytes.
	want := "AP8QIDA"
	if got != want {
		t.Fatalf("base64URL = %q, want %q", got, want)
	}
}
