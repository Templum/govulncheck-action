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
	SERVERITY = "warning"                              // There are no Severities published on that page
	shortName = "vulncheck"
	fullName  = "Golang Vulncheck"
	uri       = "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck"
)

var rootPath = "file:///"

type SarifReporter struct {
	output io.Writer
	report *sarif.Report
	run    *sarif.Run

	importLookup  *vulncheck.ImportGraph
	callLookup    *vulncheck.CallGraph
	requireLookup *vulncheck.RequireGraph
}

func NewSarifReporter(file io.Writer) *SarifReporter {
	return &SarifReporter{output: file, report: nil, run: nil}
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

func (sr *SarifReporter) InitLookups(importGraph *vulncheck.ImportGraph, callGraph *vulncheck.CallGraph, requireGraph *vulncheck.RequireGraph) {
	fmt.Println("Initialized Lookups on Reporter")
	sr.importLookup = importGraph
	sr.callLookup = callGraph
	sr.requireLookup = requireGraph
}

func (sr *SarifReporter) AddRule(vuln vulncheck.Vuln) {
	text, markdown := sr.generateHelp(vuln)

	// sr.run.AddRule does check if the rule is present prior to adding it
	sr.run.AddRule(vuln.OSV.ID).
		WithName(RULENAME).
		WithDescription(vuln.OSV.ID).
		WithFullDescription(sarif.NewMultiformatMessageString(vuln.OSV.Details)).
		WithHelp(sarif.NewMultiformatMessageString(text).WithMarkdown(markdown)).
		WithDefaultConfiguration(sarif.NewReportingConfiguration().WithLevel(SERVERITY)).
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

func (sr *SarifReporter) DoesRuleExist(osvID string) bool {
	for _, rule := range sr.run.Tool.Driver.Rules {
		if rule.ID == osvID {
			return true
		}
	}

	return false
}

func (sr *SarifReporter) AddResult(vuln vulncheck.Vuln) {

	region := sarif.NewRegion(). // TODO: Need to get from call sync
					WithStartLine(1).
					WithEndLine(1).
					WithStartColumn(1).
					WithEndColumn(1)

	location := sarif.NewPhysicalLocation().
		WithArtifactLocation(sarif.NewSimpleArtifactLocation("").WithUriBaseId("ROOTPATH")). // TODO: get Location
		WithRegion(region)

	sr.run.AddResult(
		sarif.NewRuleResult(vuln.OSV.ID).
			WithLevel(SERVERITY).
			WithMessage(sarif.NewTextMessage("Found a vulnerability")). //TODO: Create text sharing also fixed version (if avilable)
			WithRuleIndex(0).                                           //TODO: Need to get rule based on vuln.OSV.ID
			WithLocations([]*sarif.Location{sarif.NewLocationWithPhysicalLocation(location)}),
	)
}

func (sr *SarifReporter) Flush() error {
	sr.run.ColumnKind = "utf16CodeUnits"
	sr.run.OriginalUriBaseIDs = map[string]*sarif.ArtifactLocation{
		"ROOTPATH": {URI: &rootPath},
	}

	sr.report.AddRun(sr.run)
	return sr.report.PrettyWrite(sr.output)
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

func (sr *SarifReporter) generateHelp(vuln vulncheck.Vuln) (text string, markdown string) {
	fixVersion := searchFixVersion(vuln.OSV.Affected)

	return fmt.Sprintf("Vulnerability %s \n Module: %s \n Package: %s \n Fixed in Version: %s \n", vuln.OSV.ID, vuln.ModPath, vuln.PkgPath, fixVersion),
		fmt.Sprintf("**Vulnerability %s**\n| Module | Package | Fixed in Version |\n| --- | --- | --- | --- |\n|%s|%s|%s|\n", vuln.OSV.ID, vuln.ModPath, vuln.PkgPath, fixVersion)
}
