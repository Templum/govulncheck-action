package sarif

import (
	"fmt"
	"io"
	"strings"

	"github.com/Templum/govulncheck-action/pkg/types"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/rs/zerolog"
	"golang.org/x/vuln/osv"
)

const (
	ruleName  = "LanguageSpecificPackageVulnerability"
	severity  = "warning"
	shortName = "govulncheck"
	fullName  = "Golang Vulncheck"
	uri       = "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck"
	baseURI   = "SRCROOT"
	envRepo   = "GITHUB_REPOSITORY"
)

type SarifReporter struct {
	report *sarif.Report
	run    *sarif.Run
	log    zerolog.Logger

	workDir string
}

func NewSarifReporter(logger zerolog.Logger, workDir string) types.Reporter {
	return &SarifReporter{report: nil, run: nil, log: logger, workDir: workDir}
}

func (sr *SarifReporter) Convert(result *types.Result) error {
	sr.createEmptyReport("initial")

	sr.log.Debug().Msgf("Scan result shows the code is affected by %d vulnerabilities", len(result.Vulns))
	for _, vuln := range result.Vulns {
		sr.addRule(vuln.Osv)

		for _, mods := range vuln.Modules {
			for _, pkg := range mods.Packages {
				if len(pkg.CallStacks) > 0 {
					for _, callStack := range pkg.CallStacks {
						// Vulnerable code is directly called
						sr.addDirectCallResult(vuln.Osv.ID, pkg, callStack)
					}
				} else {
					// Vulnerable code is direct or indirect imported
					sr.addImportResult(vuln.Osv.ID, pkg)
				}
			}
		}

	}

	sr.log.Info().Int("Vulnerabilities", len(sr.run.Tool.Driver.Rules)).Int("Call Sites", len(sr.run.Results)).Msg("Conversion yielded following stats")
	return nil
}

func (sr *SarifReporter) Write(dest io.Writer) error {
	sr.report.AddRun(sr.run)

	return sr.report.PrettyWrite(dest)
}

func (sr *SarifReporter) createEmptyReport(vulncheckVersion string) {
	report, _ := sarif.New(sarif.Version210)

	run := sarif.NewRunWithInformationURI(shortName, uri)
	run.Tool.Driver.WithVersion("0.0.1") // TODO: Get version from tag
	run.Tool.Driver.WithFullName(fullName)
	run.ColumnKind = "utf16CodeUnits"

	sr.report = report
	sr.run = run
}

func (sr *SarifReporter) addRule(vuln *osv.Entry) {
	text, markdown := sr.generateRuleHelp(vuln)

	// sr.run.AddRule does check if the rule is present prior to adding it
	sr.run.AddRule(vuln.ID).
		WithName(ruleName).
		WithDescription(vuln.ID).
		WithFullDescription(sarif.NewMultiformatMessageString(vuln.Details)).
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
			"aliases":   vuln.Aliases,
		}).
		WithHelpURI(fmt.Sprintf("https://pkg.go.dev/vuln/%s", vuln.ID))
}

func (sr *SarifReporter) addDirectCallResult(vulnID string, pkg *types.Package, callStack types.CallStack) {
	entry := callStack.Frames[0]

	result := sarif.NewRuleResult(vulnID).
		WithLevel(severity).
		WithMessage(sarif.NewMessage().WithText(callStack.Summary))

	sr.log.Debug().
		Str("Symbol", callStack.Symbol).
		Msgf("Adding a result for %s called from %s", vulnID, entry.Position)

	region := sarif.NewRegion().
		WithStartLine(entry.Position.Line).
		WithEndLine(entry.Position.Line).
		WithStartColumn(entry.Position.Column).
		WithEndColumn(entry.Position.Column).
		WithCharOffset(entry.Position.Offset)

	location := sarif.NewPhysicalLocation().
		WithArtifactLocation(sarif.NewSimpleArtifactLocation(sr.makePathRelative(entry.Position.Filename)).WithUriBaseId(baseURI)).
		WithRegion(region)

	result.WithLocations([]*sarif.Location{sarif.NewLocationWithPhysicalLocation(location)})

	if ruleIdx := sr.getRule(vulnID); ruleIdx >= 0 {
		result.WithRuleIndex(ruleIdx)
		sr.run.AddResult(result)
	}
}

func (sr *SarifReporter) addImportResult(vulnID string, pkg *types.Package) {
	result := sarif.NewRuleResult(vulnID).
		WithLevel(severity).
		WithMessage(sarif.NewMessage().WithText(fmt.Sprintf("Package %s is vulnerable to %s, but your code doesn't appear to call any vulnerable function directly. You may not need to take any action.", pkg.Path, vulnID)))

	sr.log.Debug().
		Str("Path", pkg.Path).
		Msgf("Adding a result related to an import exposed to %s", vulnID)

	region := sarif.NewRegion().
		WithStartLine(0).
		WithEndLine(0).
		WithStartColumn(0).
		WithEndColumn(0).
		WithCharOffset(0)

	location := sarif.NewPhysicalLocation().
		WithArtifactLocation(sarif.NewSimpleArtifactLocation("go.mod").WithUriBaseId(baseURI)).
		WithRegion(region)

	result.WithLocations([]*sarif.Location{sarif.NewLocationWithPhysicalLocation(location)})

	if ruleIdx := sr.getRule(vulnID); ruleIdx >= 0 {
		result.WithRuleIndex(ruleIdx)
		sr.run.AddResult(result)
	}
}

func (sr *SarifReporter) getRule(ruleId string) int {
	for idx, rule := range sr.run.Tool.Driver.Rules {
		if rule.ID == ruleId {
			return idx
		}
	}
	return -1
}

func (sr *SarifReporter) makePathRelative(absolute string) string {
	return strings.ReplaceAll(absolute, sr.workDir, "")
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

func (sr *SarifReporter) searchPackage(versions []osv.Affected) string {
	for _, current := range versions {
		return current.Package.Name
	}

	return "N/A"
}

func (sr *SarifReporter) generateRuleHelp(vuln *osv.Entry) (text string, markdown string) {
	fixVersion := sr.searchFixVersion(vuln.Affected)
	pkg := sr.searchPackage(vuln.Affected)

	uri := fmt.Sprintf("https://pkg.go.dev/vuln/%s", vuln.ID)

	return fmt.Sprintf("Vulnerability %s \n Package: %s \n Fixed in Version: %s \n", vuln.ID, pkg, fixVersion),
		fmt.Sprintf("**Vulnerability [%s](%s)**\n%s\n| Package | Fixed in Version |\n| --- |:---:|\n|%s|%s|\n", vuln.ID, uri, vuln.Details, pkg, fixVersion)
}
