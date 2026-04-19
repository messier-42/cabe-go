package main

import "testing"

func TestParseFormat(t *testing.T) {
	ok := []string{"text", "json"}
	bad := []string{"", "TEXT", "JSON", "Text", "xml", " text", "text "}

	for _, s := range ok {
		if _, err := ParseFormat(s); err != nil {
			t.Errorf("ParseFormat(%q): unexpected error: %v", s, err)
		}
	}
	for _, s := range bad {
		if _, err := ParseFormat(s); err == nil {
			t.Errorf("ParseFormat(%q): expected error, got nil", s)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	ok := []string{"debug", "info", "warn", "error"}
	bad := []string{"", "DEBUG", "warning", "err", "fatal", "trace", " info ", "Info"}

	for _, s := range ok {
		if _, err := ParseSeverity(s); err != nil {
			t.Errorf("ParseSeverity(%q): unexpected error: %v", s, err)
		}
	}
	for _, s := range bad {
		if _, err := ParseSeverity(s); err == nil {
			t.Errorf("ParseSeverity(%q): expected error, got nil", s)
		}
	}
}

func TestSeverityString(t *testing.T) {
	cases := map[Severity]string{
		SeverityDebug: "debug",
		SeverityInfo:  "info",
		SeverityWarn:  "warn",
		SeverityError: "error",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", int(s), got, want)
		}
	}
}
