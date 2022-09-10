package vulncheck

import (
	"time"
)

type AffectsRangeType string

const (
	TypeUnspecified AffectsRangeType = "UNSPECIFIED"
	TypeGit         AffectsRangeType = "GIT"
	TypeSemver      AffectsRangeType = "SEMVER"
)

type Ecosystem string

const GoEcosystem Ecosystem = "Go"

type Package struct {
	Name      string    `json:"name"`
	Ecosystem Ecosystem `json:"ecosystem"`
}

type RangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type AffectsRange struct {
	Type   AffectsRangeType `json:"type"`
	Events []RangeEvent     `json:"events"`
}

type Affects []AffectsRange

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Affected struct {
	Package           Package           `json:"package"`
	Ranges            Affects           `json:"ranges,omitempty"`
	DatabaseSpecific  DatabaseSpecific  `json:"database_specific"`
	EcosystemSpecific EcosystemSpecific `json:"ecosystem_specific"`
}

type DatabaseSpecific struct {
	URL string `json:"url"`
}

// EcosytemSpecificImport contains additional information about an affected package.
type EcosystemSpecificImport struct {
	// Path is the package import path.
	Path string `json:"path,omitempty"`

	// GOOS is the execution operating system where the symbols appear, if
	// known.
	GOOS []string `json:"goos,omitempty"`

	// GOARCH specifies the execution architecture where the symbols appear, if
	// known.
	GOARCH []string `json:"goarch,omitempty"`

	// Symbols is the collection of functions and methods names affected by
	// this vulnerability. Methods are listed as <recv>.<method>.
	//
	// If included, only programs which use these symbols will be marked as
	// vulnerable. If omitted, any program which imports this module will be
	// marked vulnerable.
	//
	// These should be the symbols initially detected or identified in the CVE
	// or other source.
	Symbols []string `json:"symbols,omitempty"`
}

// EcosystemSpecific contains additional information about the vulnerability
// for the Go ecosystem.
type EcosystemSpecific struct {
	// Imports is the list of affected packages within the module.
	Imports []EcosystemSpecificImport `json:"imports,omitempty"`
}

// Entry represents a OSV style JSON vulnerability database
// entry
type Entry struct {
	ID         string      `json:"id"`
	Published  time.Time   `json:"published"`
	Modified   time.Time   `json:"modified"`
	Withdrawn  *time.Time  `json:"withdrawn,omitempty"`
	Aliases    []string    `json:"aliases,omitempty"`
	Details    string      `json:"details"`
	Affected   []Affected  `json:"affected"`
	References []Reference `json:"references,omitempty"`
}
