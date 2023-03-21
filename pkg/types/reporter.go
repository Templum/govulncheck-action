package types

import (
	"io"
)

type Reporter interface {
	Convert(result []Finding) error
	Write(dest io.Writer) error
}
