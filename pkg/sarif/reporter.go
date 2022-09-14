package sarif

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Templum/govulncheck-action/pkg/types"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/rs/zerolog"
	"golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
)

const (
	ruleName  = "LanguageSpecificPackageVulnerability"
	severity  = "warning"
	shortName = "govulncheck"
	fullName  = "Golang Vulncheck"
	uri       = "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck"
	baseURI   = "SRCROOT"
)

type SarifReporter struct {
	report *sarif.Report
	run    *sarif.Run
	log    zerolog.Logger

	workDir string
}

func NewSarifReporter(logger zerolog.Logger) types.Reporter {
	localDir, _ := os.Getwd()

	return &SarifReporter{report: nil, run: nil, log: logger, workDir: localDir}
}

func (sr *SarifReporter) Convert(result *vulncheck.Result) error {
	if err := sr.createEmptyReport("initial"); err != nil {
		return fmt.Errorf("failed to create an empty sarif report due to %v", err)
	}

	for _, current := range result.Vulns {
		sr.addRule(*current)

		if current.CallSink == 0 {
			if len(result.Imports.Packages) >= current.ImportSink {
				pkg := result.Imports.Packages[current.ImportSink]
				message := fmt.Sprintf("Project is indirectly using vulnerable package %s", pkg.Path)

				sr.addResult(current, message, nil)
			}
		} else {
			if len(result.Calls.Functions) >= current.CallSink {
				for _, call := range result.Calls.Functions[current.CallSink].CallSites {
					// Only reporting code that is used
					if strings.Contains(call.Pos.Filename, sr.workDir) {
						parent := result.Calls.Functions[call.Parent]
						message := sr.generateResultMessage(current, call, parent)

						sr.addResult(current, message, call)
					}
				}
			}
		}

	}

	return nil
}

func (sr *SarifReporter) Write(dest io.Writer) error {
	sr.run.ColumnKind = "utf16CodeUnits"
	sr.report.AddRun(sr.run)

	return sr.report.PrettyWrite(dest)
}

func (sr *SarifReporter) createEmptyReport(vulncheckVersion string) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRunWithInformationURI(shortName, uri)
	run.Tool.Driver.WithVersion("0.0.1") // TODO: Get version from tag
	run.Tool.Driver.WithFullName(fullName)

	sr.report = report
	sr.run = run

	return nil
}

func (sr *SarifReporter) addRule(vuln vulncheck.Vuln) {
	text, markdown := sr.generateRuleHelp(vuln)

	// sr.run.AddRule does check if the rule is present prior to adding it
	sr.run.AddRule(vuln.OSV.ID).
		WithName(ruleName).
		WithDescription(vuln.OSV.ID).
		WithFullDescription(sarif.NewMultiformatMessageString(vuln.OSV.Details)).
		WithHelp(sarif.NewMultiformatMessageString(text).WithMarkdown(markdown)).
		WithDefaultConfiguration(sarif.NewReportingConfiguration().WithLevel(severity)).
		WithProperties(sarif.Properties{
			"tags": []string{
				"vulnerability",
				"go",
				"golang",
				"security",
			},
			"precision": "very-high",
			"aliases":   vuln.OSV.Aliases,
		}).
		WithHelpURI(fmt.Sprintf("https://pkg.go.dev/vuln/%s", vuln.OSV.ID))
}

func (sr *SarifReporter) addResult(vuln *vulncheck.Vuln, message string, call *vulncheck.CallSite) {
	sr.log.Debug().
		Str("ID", vuln.OSV.ID).
		Str("Pkg", vuln.PkgPath).
		Str("Symbol", vuln.Symbol).
		Msg("Adding a new Result to the Sarif Report")

	result := sarif.NewRuleResult(vuln.OSV.ID).
		WithLevel(severity).
		WithMessage(sarif.NewTextMessage(message))

	if call != nil {
		region := sarif.NewRegion().
			WithStartLine(call.Pos.Line).
			WithEndLine(call.Pos.Line).
			WithStartColumn(call.Pos.Column).
			WithEndColumn(call.Pos.Column).
			WithCharOffset(call.Pos.Offset)

		location := sarif.NewPhysicalLocation().
			WithArtifactLocation(sarif.NewSimpleArtifactLocation(sr.makePathRelative(call.Pos.Filename)).WithUriBaseId(baseURI)).
			WithRegion(region)

		result.WithLocations([]*sarif.Location{sarif.NewLocationWithPhysicalLocation(location)})
	}

	ruleIdx := sr.getRuleIndex(vuln.OSV.ID)
	if ruleIdx >= 0 {
		result.WithRuleIndex(ruleIdx)
		sr.run.AddResult(result)
	}
}

func (sr *SarifReporter) getRuleIndex(ruleId string) int {
	for idx, rule := range sr.run.Tool.Driver.Rules {
		if rule.ID == ruleId {
			return idx
		}
	}
	return -1
}

func (sr *SarifReporter) generateResultMessage(vuln *vulncheck.Vuln, call *vulncheck.CallSite, parent *vulncheck.FuncNode) string {
	relativeFile := sr.makePathRelative(call.Pos.Filename)

	caller := fmt.Sprintf("%s:%d:%d %s.%s", relativeFile, call.Pos.Line, call.Pos.Column, parent.PkgPath, parent.Name)
	calledVuln := fmt.Sprintf("%s.%s", vuln.ModPath, vuln.Symbol)

	return fmt.Sprintf("%s calls %s which has vulnerability %s", caller, calledVuln, vuln.OSV.ID)
}

func (sr *SarifReporter) makePathRelative(absolute string) string {
	return strings.Replace(absolute, sr.workDir, "", 1)
}

func (sr *SarifReporter) searchFixVersion(versions []osv.Affected) string {
	for _, current := range versions {
		for _, r := range current.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}

	return "None"
}

func (sr *SarifReporter) generateRuleHelp(vuln vulncheck.Vuln) (text string, markdown string) {
	fixVersion := sr.searchFixVersion(vuln.OSV.Affected)
	uri := fmt.Sprintf("https://pkg.go.dev/vuln/%s", vuln.OSV.ID)

	return fmt.Sprintf("Vulnerability %s \n Module: %s \n Package: %s \n Fixed in Version: %s \n", vuln.OSV.ID, vuln.ModPath, vuln.PkgPath, fixVersion),
		fmt.Sprintf("**Vulnerability [%s](%s)**\n%s\n| Module | Package | Fixed in Version |\n| --- | --- |:---:|\n|%s|%s|%s|\n", vuln.OSV.ID, uri, vuln.OSV.Details, vuln.ModPath, vuln.PkgPath, fixVersion)
}
