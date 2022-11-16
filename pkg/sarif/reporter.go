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
			for _, pkgs := range mods.Packages {
				for _, callStack := range pkgs.CallStacks {
					text, markdown := sr.generateResultHelp(vuln.Osv, callStack)
					sr.addResult(vuln.Osv, callStack, text, markdown)
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

func (sr *SarifReporter) addResult(vuln *osv.Entry, callStack types.CallStack, text string, markdown string) {
	entry := callStack.Frames[0]

	result := sarif.NewRuleResult(vuln.ID).
		WithLevel(severity).
		WithMessage(sarif.NewMessage().WithMarkdown(markdown).WithText(text))

	if entry != nil {
		sr.log.Debug().
			Str("Symbol", callStack.Symbol).
			Msgf("Add result for %s called from %s", vuln.ID, entry.Position)

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
	}

	// TODO: Research option to provide fix instructions
	// result.Fixes = append(result.Fixes, sarif.NewFix().WithDescription(fmt.Sprintf("Was fixed with version %s")))

	ruleIdx := sr.getRule(vuln.ID)
	if ruleIdx >= 0 {
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
		fmt.Sprintf("**Vulnerability [%s](%s)**\n%s\n| Package | Fixed in Version |\n| --- | --- |:---:|\n|%s|%s|\n", vuln.ID, uri, vuln.Details, pkg, fixVersion)
}

func (sr *SarifReporter) generateResultHelp(vuln *osv.Entry, callStack types.CallStack) (text string, markdown string) {
	// entry := callStack.Frames[0]

	// relativeFile := sr.makePathRelative(entry.Position.String())
	// linkToFile := fmt.Sprintf("https://github.com/%s/blob/main/%s#L%d", os.Getenv(envRepo), sr.makePathRelative(entry.Position.Filename), entry.Position.Line)
	// linkToVuln := fmt.Sprintf("https://pkg.go.dev/vuln/%s", vuln.ID)

	var txtBuilder strings.Builder
	var markBuilder strings.Builder

	txtBuilder.WriteString(callStack.Summary)
	markBuilder.WriteString(callStack.Summary)

	return txtBuilder.String(), markBuilder.String()
}
