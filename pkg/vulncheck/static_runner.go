package vulncheck

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/rs/zerolog"
	"golang.org/x/vuln/vulncheck"
)

type StaticScanner struct {
	log  zerolog.Logger
	path string
}

func NewLocalScanner(logger zerolog.Logger, pathToFile string) Scanner {
	return &StaticScanner{log: logger, path: pathToFile}
}

func (r *StaticScanner) Scan() (*vulncheck.Result, error) {
	out, _ := os.ReadFile(r.path)

	var result vulncheck.Result
	err := json.Unmarshal(out, &result)
	if err != nil {
		return nil, errors.New("scan failed to produce proper report")
	}

	r.log.Debug().Msgf("Successfully parsed report located at %s", r.path)
	return &result, nil
}
