package vulncheck

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"

	"github.com/rs/zerolog"
	"golang.org/x/vuln/vulncheck"
)

const (
	command    = "govulncheck"
	flag       = "-json"
	envPackage = "PACKAGE"
)

type Scanner interface {
	Scan() (*vulncheck.Result, error)
}

type CmdScanner struct {
	log     zerolog.Logger
	workDir string
}

func NewScanner(logger zerolog.Logger, workDir string) Scanner {
	return &CmdScanner{log: logger, workDir: workDir}
}

func (r *CmdScanner) Scan() (*vulncheck.Result, error) {
	pkg := os.Getenv(envPackage)
	r.log.Info().Msgf("Running govulncheck for package %s in dir %s", pkg, r.workDir)

	cmd := exec.Command(command, flag, pkg)
	cmd.Dir = r.workDir

	out, cmdErr := cmd.Output()
	if err, ok := cmdErr.(*exec.ExitError); ok {
		if len(err.Stderr) > 0 {
			r.log.Error().
				Err(err).
				Str("Stderr", string(err.Stderr)).
				Msg("govulncheck exited with none 0 code")
		}

	} else if cmdErr != nil {
		return nil, cmdErr
	}

	var result vulncheck.Result
	err := json.Unmarshal(out, &result)
	if err != nil {
		r.log.Error().Err(err).Msg("parsing govulncheck output yielded error")
		return nil, errors.New("scan failed to produce proper report")
	}

	r.log.Info().Msg("Successfully scanned project")
	return &result, nil
}
