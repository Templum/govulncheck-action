package action

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadRuntimeInfoFromEnv(t *testing.T) {
	t.Run("should go runtime information from go env", func(t *testing.T) {
		info := ReadRuntimeInfoFromEnv()

		assert.NotNil(t, info, "should not return nil")

		assert.Equal(t, runtime.Version(), info.Version)
		assert.Equal(t, runtime.GOOS, info.Os)
		assert.Equal(t, runtime.GOARCH, info.Arch)
	})
}
