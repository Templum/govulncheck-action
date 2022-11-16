package vulncheck

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"

	"github.com/Templum/govulncheck-action/pkg/types"
	"github.com/rs/zerolog"
)

const (
	command    = "govulncheck"
	flag       = "-json"
	envPackage = "PACKAGE"
)

type Scanner interface {
	Scan() (*types.Result, error)
}

type CmdScanner struct {
	log     zerolog.Logger
	workDir string
}

func NewScanner(logger zerolog.Logger, workDir string) Scanner {
	return &CmdScanner{log: logger, workDir: workDir}
}

func (r *CmdScanner) Scan() (*types.Result, error) {
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

	var result types.Result
	err := json.Unmarshal(out, &result)
	if err != nil {
		r.log.Error().Err(err).Msg("parsing govulncheck output yielded error")
		return nil, errors.New("scan failed to produce proper report")
	}

	r.log.Info().Msg("Successfully scanned project")

	if os.Getenv("DEBUG") == "true" {
		fileName := "raw-report.json"
		reportFile, err := os.Create(fileName)

		r.log.Debug().Str("fileName", fileName).Msg("Making a copy of the raw vulncheck json report which can be exposed for debugging")

		if err != nil {
			r.log.Debug().Err(err).Msg("Failed to create copy will proceed with normal flow")
			return &result, nil
		}

		defer reportFile.Close()

		_, err = reportFile.Write(out)
		if err != nil {
			r.log.Debug().Err(err).Msg("Failed to write copy to disk will proceed with normal flow")
		}
	}

	return &result, nil
}
