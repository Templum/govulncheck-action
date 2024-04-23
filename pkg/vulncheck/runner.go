package vulncheck

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
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
	Scan() (*types.Report, error)
}

type CLIScanner struct {
	log       zerolog.Logger
	invokeCli CLIInvoker
	workDir   string
}

type CLIInvoker func(workDir string, command string, flag string, pkg string) ([]byte, error)

func NewScanner(logger zerolog.Logger, workDir string, inLocalMode bool) Scanner {
	scanner := CLIScanner{log: logger, workDir: workDir}

	if inLocalMode {
		scanner.invokeCli = staticLocalCli
	} else {
		scanner.invokeCli = vulncheckCli
	}

	return &scanner
}

func (r *CLIScanner) Scan() (*types.Report, error) {
	pkg := os.Getenv(envPackage)
	r.log.Info().Msgf("Running govulncheck for package %s in dir %s", pkg, r.workDir)

	out, cmdErr := r.invokeCli(r.workDir, command, flag, pkg)

	if os.Getenv("DEBUG") == "true" {
		r.dumpRawReport(string(out))
	}

	// govulncheck exits with none zero exit code if any vulnerability are found
	if err, ok := cmdErr.(*exec.ExitError); ok {
		// Only if stderr is present the CLI failed
		if len(err.Stderr) > 0 {
			receivedError := string(err.Stderr)

			if strings.Contains(receivedError, "go:") {
				receivedError = strings.Trim(receivedError[strings.Index(receivedError, "go:")+3:], " ")
			}

			r.log.Error().
				Err(err).
				Str("Stderr", receivedError).
				Msg("govulncheck exited with none 0 code")

			// Building up a set of known "mistakes"
			if strings.Contains(receivedError, "requires go >=") {
				return nil, fmt.Errorf("the used go version is lower than required by your code. original error: %s", receivedError)
			}

			return nil, fmt.Errorf("running govulncheck binary produced %s", receivedError)
		}
	}

	report := r.findFindingsInStream(out)

	r.log.Info().Msg("Successfully scanned project")
	return report, nil
}

// findFindingsInStream is going over the raw output of govulncheck which at the moment contains multiple json objects and tries to locate the report
func (r *CLIScanner) findFindingsInStream(stream []byte) *types.Report {
	var vulnerabilities []types.Entry
	var findings []types.Finding
	var version string

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
			r.log.Warn().Str("Message", rawMsg).Msgf("Parsing message yielded %v", err)
			continue
		}

		if msg.Config != nil {
			r.log.Info().
				Str("Protocol Version", msg.Config.ProtocolVersion).
				Str("Scanner Version", msg.Config.ScannerVersion).
				Str("Database", msg.Config.DB).
				Msg("govulncheck information")

			version = msg.Config.ScannerVersion
		}

		if msg.Progress != nil && len(msg.Progress.Message) > 0 {
			r.log.Info().Msg(msg.Progress.Message)
		}

		if msg.Finding != nil {
			findings = append(findings, *msg.Finding)
		}

		if msg.OSV != nil {
			vulnerabilities = append(vulnerabilities, *msg.OSV)
		}
	}

	return &types.Report{Vulnerabilities: vulnerabilities, Findings: findings, Version: version}
}

// dumpRawReport takes the raw report and writes it to raw-report.json if something fails it will proceed with the regular flow
func (r *CLIScanner) dumpRawReport(rawReport string) {
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

// vulncheckCli
func vulncheckCli(workDir string, command string, flag string, pkg string) ([]byte, error) {
	cmd := exec.Command(command, flag, pkg)
	cmd.Dir = workDir

	out, err := cmd.Output()
	return out, err
}

func staticLocalCli(workDir string, command string, flag string, pkg string) ([]byte, error) {
	path := path.Join(workDir, "hack", "found.stream")
	out, _ := os.ReadFile(path)

	return out, nil
}
