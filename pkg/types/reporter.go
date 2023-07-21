package types

import (
	"io"
)

type Reporter interface {
	Convert(result *Report) error
	Write(dest io.Writer) error
}

// TODO: Config contains govulncheck version

type Report struct {
	Vulnerabilities []Entry
	Findings        []Finding
}
