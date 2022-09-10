package sarif

import (
	"fmt"
	"io"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/vuln/osv"
	"golang.org/x/vuln/vulncheck"
)

const (
	RULENAME  = "LanguageSpecificPackageVulnerability" // TODO: Research if more specific rule name is possible
	SEVERITY  = "warning"                              // There are no Severities published on that page
	shortName = "govulncheck"
	fullName  = "Golang Vulncheck"
	uri       = "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck"
)

var rootPath = "file:///"

type SarifReporter struct {
	report *sarif.Report
	run    *sarif.Run
}

func NewSarifReporter() *SarifReporter {
	return &SarifReporter{report: nil, run: nil}
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
		WithName(RULENAME).
		WithDescription(vuln.OSV.ID).
		WithFullDescription(sarif.NewMultiformatMessageString(vuln.OSV.Details)).
		WithHelp(sarif.NewMultiformatMessageString(text).WithMarkdown(markdown)).
		WithDefaultConfiguration(sarif.NewReportingConfiguration().WithLevel(SEVERITY)).
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

func (sr *SarifReporter) AddCallResult(vuln *vulncheck.Vuln, call *vulncheck.CallSite) {
	result := sarif.NewRuleResult(vuln.OSV.ID).
		WithLevel(SEVERITY).
		WithMessage(sarif.NewTextMessage(fmt.Sprintf("Vulnerable Code [%s] is getting called", call.Name)))
	region := sarif.NewRegion().
		WithStartLine(call.Pos.Line).
		WithEndLine(call.Pos.Line).
		WithStartColumn(call.Pos.Column).
		WithEndColumn(call.Pos.Column).
		WithCharOffset(call.Pos.Offset)

	location := sarif.NewPhysicalLocation().
		WithArtifactLocation(sarif.NewSimpleArtifactLocation(call.Pos.Filename).WithUriBaseId("ROOTPATH")).
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
		WithLevel(SEVERITY).
		WithMessage(sarif.NewTextMessage(fmt.Sprintf("Import of vulnerable package %s", pkg.Path)))

	ruleIdx := sr.getRuleIndex(vuln.OSV.ID)
	if ruleIdx > 0 {
		result.WithRuleIndex(ruleIdx)
		sr.run.AddResult(result)
	}
}

func (sr *SarifReporter) Flush(file io.Writer) error {
	sr.run.ColumnKind = "utf16CodeUnits"
	sr.run.OriginalUriBaseIDs = map[string]*sarif.ArtifactLocation{
		"ROOTPATH": {URI: &rootPath},
	}

	sr.report.AddRun(sr.run)
	return sr.report.PrettyWrite(file)
}

func (sr *SarifReporter) getRuleIndex(ruleId string) int {
	for idx, rule := range sr.run.Tool.Driver.Rules {
		if rule.ID == ruleId {
			return idx
		}
	}
	return -1
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

	return fmt.Sprintf("Vulnerability %s \n Module: %s \n Package: %s \n Fixed in Version: %s \n", vuln.OSV.ID, vuln.ModPath, vuln.PkgPath, fixVersion),
		fmt.Sprintf("**Vulnerability %s**\n| Module | Package | Fixed in Version |\n| --- | --- |:---:|\n|%s|%s|%s|\n\n %s", vuln.OSV.ID, vuln.ModPath, vuln.PkgPath, fixVersion, vuln.OSV.Details)
}
