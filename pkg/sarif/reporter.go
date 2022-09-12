package sarif

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
)

const (
	ruleName  = "LanguageSpecificPackageVulnerability" // TODO: Research if more specific rule name is possible
	severity  = "warning"                              // There are no Severities published on that page
	shortName = "govulncheck"
	fullName  = "Golang Vulncheck"
	uri       = "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck"
	baseURI   = "SRCROOT"
)

type Reporter interface {
	CreateEmptyReport(vulncheckVersion string) error
	AddRule(vuln vulncheck.Vuln)
	AddCallResult(vuln *vulncheck.Vuln, call *vulncheck.CallSite, parent *vulncheck.FuncNode)
	AddImportResult(vuln *vulncheck.Vuln, pkg *vulncheck.PkgNode)
}

type Report interface {
	Flush(writer io.Writer) error
}

type Reportable interface {
	Reporter
	Report
}

type SarifReporter struct {
	report *sarif.Report
	run    *sarif.Run

	workDir string
}

func NewSarifReporter() Reportable {
	localDir, _ := os.Getwd()

	return &SarifReporter{report: nil, run: nil, workDir: localDir}
}

func (sr *SarifReporter) CreateEmptyReport(vulncheckVersion string) error {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}

	run := sarif.NewRunWithInformationURI(shortName, uri)
	run.Tool.Driver.WithVersion(vulncheckVersion)
	run.Tool.Driver.WithFullName(fullName)

	sr.report = report
	sr.run = run

	return nil
}

func (sr *SarifReporter) AddRule(vuln vulncheck.Vuln) {
	text, markdown := generateRuleHelp(vuln)

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

func (sr *SarifReporter) AddCallResult(vuln *vulncheck.Vuln, call *vulncheck.CallSite, parent *vulncheck.FuncNode) {
	result := sarif.NewRuleResult(vuln.OSV.ID).
		WithLevel(severity).
		WithMessage(sarif.NewTextMessage(sr.generateResultMessage(vuln, call, parent)))
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

	ruleIdx := sr.getRuleIndex(vuln.OSV.ID)
	if ruleIdx >= 0 {
		result.WithRuleIndex(ruleIdx)
		sr.run.AddResult(result)
	}
}

func (sr *SarifReporter) AddImportResult(vuln *vulncheck.Vuln, pkg *vulncheck.PkgNode) {
	result := sarif.NewRuleResult(vuln.OSV.ID).
		WithLevel(severity).
		WithMessage(sarif.NewTextMessage(fmt.Sprintf("Import of vulnerable package %s", pkg.Path)))

	ruleIdx := sr.getRuleIndex(vuln.OSV.ID)
	if ruleIdx > 0 {
		result.WithRuleIndex(ruleIdx)
		sr.run.AddResult(result)
	}
}

func (sr *SarifReporter) Flush(writer io.Writer) error {
	sr.run.ColumnKind = "utf16CodeUnits"

	sr.report.AddRun(sr.run)
	return sr.report.PrettyWrite(writer)
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

func searchFixVersion(versions []osv.Affected) string {
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

func generateRuleHelp(vuln vulncheck.Vuln) (text string, markdown string) {
	fixVersion := searchFixVersion(vuln.OSV.Affected)
	uri := fmt.Sprintf("https://pkg.go.dev/vuln/%s", vuln.OSV.ID)

	return fmt.Sprintf("Vulnerability %s \n Module: %s \n Package: %s \n Fixed in Version: %s \n", vuln.OSV.ID, vuln.ModPath, vuln.PkgPath, fixVersion),
		fmt.Sprintf("**Vulnerability [%s](%s)**\n%s\n| Module | Package | Fixed in Version |\n| --- | --- |:---:|\n|%s|%s|%s|\n", vuln.OSV.ID, uri, vuln.OSV.Details, vuln.ModPath, vuln.PkgPath, fixVersion)
}
