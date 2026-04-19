package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

// Format selects the slog handler used to serialise log records.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

// ParseFormat accepts exactly "text" or "json". No case folding; any
// other value (including the empty string, "TEXT", "JSON") is rejected.
func ParseFormat(s string) (Format, error) {
	switch s {
	case string(FormatText):
		return FormatText, nil
	case string(FormatJSON):
		return FormatJSON, nil
	default:
		return "", fmt.Errorf("invalid log format %q: must be %q or %q", s, FormatText, FormatJSON)
	}
}

// Severity is a named type over slog.Level carrying a strict parser and
// a canonical string form. Convert with slog.Level(sev) when a slog API
// needs it.
type Severity slog.Level

const (
	SeverityDebug = Severity(slog.LevelDebug)
	SeverityInfo  = Severity(slog.LevelInfo)
	SeverityWarn  = Severity(slog.LevelWarn)
	SeverityError = Severity(slog.LevelError)
)

const (
	severityNameDebug = "debug"
	severityNameInfo  = "info"
	severityNameWarn  = "warn"
	severityNameError = "error"
)

// ParseSeverity accepts exactly "debug", "info", "warn", or "error".
// No case folding, no synonyms (e.g. "warning", "err", the empty
// string, or uppercase variants are rejected).
func ParseSeverity(s string) (Severity, error) {
	switch s {
	case severityNameDebug:
		return SeverityDebug, nil
	case severityNameInfo:
		return SeverityInfo, nil
	case severityNameWarn:
		return SeverityWarn, nil
	case severityNameError:
		return SeverityError, nil
	default:
		return 0, fmt.Errorf("invalid log severity %q: must be %q, %q, %q, or %q",
			s, severityNameDebug, severityNameInfo, severityNameWarn, severityNameError)
	}
}

func (s Severity) String() string {
	switch s {
	case SeverityDebug:
		return severityNameDebug
	case SeverityInfo:
		return severityNameInfo
	case SeverityWarn:
		return severityNameWarn
	case SeverityError:
		return severityNameError
	default:
		return slog.Level(s).String()
	}
}

// LogConfig is the resolved logging configuration. Both fields must be
// set explicitly; this type does not supply defaults. Flag/env parsing
// at the cobra layer does the defaulting.
type LogConfig struct {
	Format   Format
	Severity Severity
}

// NewLogger constructs a *slog.Logger from cfg, writing to os.Stderr.
// An unrecognised Format value falls back to text handler so that a
// logger is always produced; ParseFormat is the right gate for
// rejecting bad input before it reaches here.
func NewLogger(cfg LogConfig) *slog.Logger {
	return newLoggerWithWriter(os.Stderr, cfg)
}

func newLoggerWithWriter(w io.Writer, cfg LogConfig) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.Level(cfg.Severity)}
	switch cfg.Format {
	case FormatJSON:
		return slog.New(slog.NewJSONHandler(w, opts))
	case FormatText:
		return slog.New(slog.NewTextHandler(w, opts))
	default:
		return slog.New(slog.NewTextHandler(w, opts))
	}
}
