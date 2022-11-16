package types

import (
	"io"
)

type Reporter interface {
	Convert(result *Result) error
	Write(dest io.Writer) error
}
