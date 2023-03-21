package vulncheck

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/Templum/govulncheck-action/pkg/types"
	"github.com/rs/zerolog"
)

type StaticScanner struct {
	log  zerolog.Logger
	path string
}

func NewLocalScanner(logger zerolog.Logger, pathToFile string) Scanner {
	return &StaticScanner{log: logger, path: pathToFile}
}

func (r *StaticScanner) Scan() ([]types.Finding, error) {
	out, _ := os.ReadFile(r.path)

	var result []types.Finding
	err := json.Unmarshal(out, &result)
	if err != nil {
		return nil, errors.New("scan failed to produce proper report")
	}

	r.log.Debug().Msgf("Successfully parsed report located at %s", r.path)
	return result, nil
}
