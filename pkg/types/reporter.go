package types

import (
	"io"
)

type Reporter interface {
	Convert(result *Report) error
	Write(dest io.Writer) error
}

type Report struct {
	Vulnerabilities []Entry
	Findings        []Finding
	Version         string
}
