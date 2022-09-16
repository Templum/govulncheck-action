package types

import (
	"io"
)

type Reporter interface {
	Convert(result VulnerableStacks) error
	Write(dest io.Writer) error
}
