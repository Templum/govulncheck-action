package vulncheck

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	"github.com/Templum/govulncheck-action/pkg/types"
	"github.com/rs/zerolog"
)

const (
	command    = "govulncheck"
	flag       = "-json"
	envPackage = "PACKAGE"
)

type Scanner interface {
	Scan() ([]types.Finding, error)
}

type CmdScanner struct {
	log     zerolog.Logger
	workDir string
}

func NewScanner(logger zerolog.Logger, workDir string) Scanner {
	return &CmdScanner{log: logger, workDir: workDir}
}

func (r *CmdScanner) Scan() ([]types.Finding, error) {
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

	report := r.findReportInStream(out)

	if os.Getenv("DEBUG") == "true" {
		r.dumpRawReport(string(out))
	}

	r.log.Info().Msg("Successfully scanned project")
	return report, nil

}

// findReportInStream is going over the raw output of govulncheck which at the moment contains multiple json objects and tries to locate the report
func (r *CmdScanner) findReportInStream(stream []byte) []types.Finding {
	var findings []types.Finding
	MESSAGE_SEPARATOR := "\n{\n"

	messages := strings.SplitN(string(stream), MESSAGE_SEPARATOR, -1)

	for _, rawMsg := range messages {
		// Fixing broken JSON where needed
		if !strings.HasPrefix(rawMsg, "{") {
			rawMsg = "{\n" + rawMsg
		}

		var msg types.StreamMessage
		err := json.Unmarshal([]byte(rawMsg), &msg)
		if err != nil {
			r.log.Warn().Str("Message", rawMsg).Msg("Found message in stream that could not be parsed")
			continue
		}

		if msg.Vulnerability != nil {
			findings = append(findings, *msg.Vulnerability)
		}
	}

	return findings
}

// dumpRawReport takes the raw report and writes it to raw-report.json if something fails it will proceed with the regular flow
func (r *CmdScanner) dumpRawReport(rawReport string) {
	fileName := "raw-report.json"
	reportFile, err := os.Create(fileName)

	r.log.Debug().Str("fileName", fileName).Msg("Making a copy of the raw vulncheck json report which can be exposed for debugging")

	if err != nil {
		r.log.Debug().Err(err).Msg("Failed to create copy will proceed with normal flow")
		return
	}

	defer reportFile.Close()

	_, err = reportFile.Write([]byte(rawReport))
	if err != nil {
		r.log.Debug().Err(err).Msg("Failed to write copy to disk will proceed with normal flow")
	}
}
