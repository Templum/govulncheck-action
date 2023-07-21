package types

import (
	"time"
)

// StreamMessage (Message) links to: https://github.com/golang/vuln/blob/1568f338f20421c10ef3dcf745755769c4e52a68/internal/govulncheck/govulncheck.go#L21
type StreamMessage struct {
	Config   *Config   `json:"config,omitempty"`
	Progress *Progress `json:"progress,omitempty"`
	OSV      *Entry    `json:"osv,omitempty"`
	Finding  *Finding  `json:"finding,omitempty"`
}

// Config links to: https://github.com/golang/vuln/blob/1568f338f20421c10ef3dcf745755769c4e52a68/internal/govulncheck/govulncheck.go#L31C1-L58C2
type Config struct {
	// ProtocolVersion specifies the version of the JSON protocol.
	ProtocolVersion string `json:"protocol_version"`

	// ScannerName is the name of the tool, for example, govulncheck.
	//
	// We expect this JSON format to be used by other tools that wrap
	// govulncheck, which will have a different name.
	ScannerName string `json:"scanner_name,omitempty"`

	// ScannerVersion is the version of the tool.
	ScannerVersion string `json:"scanner_version,omitempty"`

	// DB is the database used by the tool, for example,
	// vuln.go.dev.
	DB string `json:"db,omitempty"`

	// LastModified is the last modified time of the data source.
	DBLastModified *time.Time `json:"db_last_modified,omitempty"`

	// GoVersion is the version of Go used for analyzing standard library
	// vulnerabilities.
	GoVersion string `json:"go_version,omitempty"`

	// ScanLevel instructs govulncheck to analyze at a specific level of detail.
	// Valid values include module, package and symbol.
	ScanLevel string `json:"scan_level,omitempty"`
}

// Progress links to: https://github.com/golang/vuln/blob/1568f338f20421c10ef3dcf745755769c4e52a68/internal/govulncheck/govulncheck.go#L64
type Progress struct {
	// A time stamp for the message.
	Timestamp *time.Time `json:"time,omitempty"`

	// Message is the progress message.
	Message string `json:"message,omitempty"`
}

// Finding links to: https://github.com/golang/vuln/blob/1568f338f20421c10ef3dcf745755769c4e52a68/internal/govulncheck/govulncheck.go#L73
type Finding struct {
	// OSV is the id of the detected vulnerability.
	OSV string `json:"osv,omitempty"`

	// FixedVersion is the module version where the vulnerability was
	// fixed. This is empty if a fix is not available.
	//
	// If there are multiple fixed versions in the OSV report, this will
	// be the fixed version in the latest range event for the OSV report.
	//
	// For example, if the range events are
	// {introduced: 0, fixed: 1.0.0} and {introduced: 1.1.0}, the fixed version
	// will be empty.
	//
	// For the stdlib, we will show the fixed version closest to the
	// Go version that is used. For example, if a fix is available in 1.17.5 and
	// 1.18.5, and the GOVERSION is 1.17.3, 1.17.5 will be returned as the
	// fixed version.
	FixedVersion string `json:"fixed_version,omitempty"`

	// Trace contains an entry for each frame in the trace.
	//
	// Frames are sorted starting from the imported vulnerable symbol
	// until the entry point. The first frame in Frames should match
	// Symbol.
	//
	// In binary mode, trace will contain a single-frame with no position
	// information.
	//
	// When a package is imported but no vulnerable symbol is called, the trace
	// will contain a single-frame with no symbol or position information.
	Trace []*Frame `json:"trace,omitempty"`
}

// Frame links to: https://github.com/golang/vuln/blob/1568f338f20421c10ef3dcf745755769c4e52a68/internal/govulncheck/govulncheck.go#L73
type Frame struct {
	// Module is the module path of the module containing this symbol.
	//
	// Importable packages in the standard library will have the path "stdlib".
	Module string `json:"module"`

	// Version is the module version from the build graph.
	Version string `json:"version,omitempty"`

	// Package is the import path.
	Package string `json:"package,omitempty"`

	// Function is the function name.
	Function string `json:"function,omitempty"`

	// Receiver is the receiver type if the called symbol is a method.
	//
	// The client can create the final symbol name by
	// prepending Receiver to FuncName.
	Receiver string `json:"receiver,omitempty"`

	// Position describes an arbitrary source position
	// including the file, line, and column location.
	// A Position is valid if the line number is > 0.
	Position *Position `json:"position,omitempty"`
}

// Position links to: https://github.com/golang/vuln/blob/1568f338f20421c10ef3dcf745755769c4e52a68/internal/govulncheck/govulncheck.go#L136
type Position struct {
	Filename string `json:"filename,omitempty"` // filename, if any
	Offset   int    `json:"offset"`             // byte offset, starting at 0
	Line     int    `json:"line"`               // line number, starting at 1
	Column   int    `json:"column"`             // column number, starting at 1 (byte count)
}

// Entry links to: https://github.com/golang/vuln/blob/1568f338f20421c10ef3dcf745755769c4e52a68/internal/osv/osv.go#L180
type Entry struct {
	// SchemaVersion is the OSV schema version used to encode this
	// vulnerability.
	SchemaVersion string `json:"schema_version,omitempty"`
	// ID is a unique identifier for the vulnerability. Required.
	// The Go vulnerability database issues IDs of the form
	// GO-<YEAR>-<ENTRYID>.
	ID string `json:"id"`
	// Modified is the time the entry was last modified. Required.
	Modified time.Time `json:"modified,omitempty"`
	// Published is the time the entry should be considered to have
	// been published.
	Published time.Time `json:"published,omitempty"`
	// Withdrawn is the time the entry should be considered to have
	// been withdrawn. If the field is missing, then the entry has
	// not been withdrawn.
	Withdrawn *time.Time `json:"withdrawn,omitempty"`
	// Aliases is a list of IDs for the same vulnerability in other
	// databases.
	Aliases []string `json:"aliases,omitempty"`
	// Summary gives a one-line, English textual summary of the vulnerability.
	// It is recommended that this field be kept short, on the order of no more
	// than 120 characters.
	Summary string `json:"summary,omitempty"`
	// Details contains additional English textual details about the vulnerability.
	Details string `json:"details"`
	// Affected contains information on the modules and versions
	// affected by the vulnerability.
	Affected []Affected `json:"affected"`
	// References contains links to more information about the
	// vulnerability.
	References []struct{} `json:"references,omitempty"`
	// Credits contains credits to entities that helped find or fix the
	// vulnerability.
	Credits []struct{} `json:"credits,omitempty"`
	// DatabaseSpecific contains additional information about the
	// vulnerability, specific to the Go vulnerability database.
	DatabaseSpecific *struct{} `json:"database_specific,omitempty"`
}

// Affected links to: https://github.com/golang/vuln/blob/1568f338f20421c10ef3dcf745755769c4e52a68/internal/osv/osv.go#L136
type Affected struct {
	// The affected Go module. Required.
	// Note that this field is called "package" in the OSV specification.
	Module Module `json:"package"`
	// The module version ranges affected by the vulnerability.
	Ranges []Range `json:"ranges,omitempty"`
	// Details on the affected packages and symbols within the module.
	EcosystemSpecific *struct{} `json:"ecosystem_specific"`
}

// Module links to: https://github.com/golang/vuln/blob/1568f338f20421c10ef3dcf745755769c4e52a68/internal/osv/osv.go#L54
type Module struct {
	// The Go module path. Required.
	// For the Go standard library, this is "stdlib".
	// For the Go toolchain, this is "toolchain."
	Path string `json:"name"`
	// The ecosystem containing the module. Required.
	// This should always be "Go".
	Ecosystem string `json:"ecosystem"`
}

// Range links to: https://github.com/golang/vuln/blob/1568f338f20421c10ef3dcf745755769c4e52a68/internal/osv/osv.go#L85C1-L85C1
type Range struct {
	// Type is the version type that should be used to interpret the
	// versions in Events. Required.
	// In this implementation, only the "SEMVER" type is supported.
	Type string `json:"type"`
	// Events is a list of versions representing the ranges in which
	// the module is vulnerable. Required.
	// The events should be sorted, and MUST represent non-overlapping
	// ranges.
	// There must be at least one RangeEvent containing a value for
	// Introduced.
	// See https://ossf.github.io/osv-schema/#examples for examples.
	Events []RangeEvent `json:"events"`
}

// RangeEvent links to: https://github.com/golang/vuln/blob/1568f338f20421c10ef3dcf745755769c4e52a68/internal/osv/osv.go#L72
type RangeEvent struct {
	// Introduced is a version that introduces the vulnerability.
	// A special value, "0", represents a version that sorts before
	// any other version, and should be used to indicate that the
	// vulnerability exists from the "beginning of time".
	Introduced string `json:"introduced,omitempty"`
	// Fixed is a version that fixes the vulnerability.
	Fixed string `json:"fixed,omitempty"`
}
