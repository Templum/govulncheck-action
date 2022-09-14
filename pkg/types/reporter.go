package types

import (
	"io"

	"golang.org/x/vuln/vulncheck"
)

type Reporter interface {
	Convert(result *vulncheck.Result) error
	Write(dest io.Writer) error
}
