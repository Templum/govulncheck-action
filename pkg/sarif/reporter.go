package sarif

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Templum/govulncheck-action/pkg/action"
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

func (sr *SarifReporter) Convert(result types.VulnerableStacks) error {
	sr.createEmptyReport("initial")

	sr.log.Debug().Msgf("Scan showed code being impacted by %d vulnerabilities", len(result))
	for vuln, callStacks := range result {
		sr.addRule(vuln)

		for _, current := range callStacks {
			// callSite can never have Call=nil Function=nil as the curator is using
			// the same method and filtering out those cases
			callSite := action.FindVulnerableCallSite(sr.workDir, current)

			text, markdown := sr.generateResultMessage(vuln, callSite, current)
			sr.addResult(vuln, callSite.Call, text, markdown)
		}

	}

	sr.log.Info().Int("Vulnerabilities", len(result)).Int("Call Sites", len(sr.run.Results)).Msg("Conversion yielded following stats")
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

func (sr *SarifReporter) addRule(vuln *vulncheck.Vuln) {
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

func (sr *SarifReporter) addResult(vuln *vulncheck.Vuln, call *vulncheck.CallSite, text string, markdown string) {
	result := sarif.NewRuleResult(vuln.OSV.ID).
		WithLevel(severity).
		WithMessage(sarif.NewMessage().WithMarkdown(markdown).WithText(text))

	if call != nil {
		sr.log.Debug().
			Str("Symbol", vuln.Symbol).
			Msgf("Add result for %s called from %s", vuln.OSV.ID, call.Pos)

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

	// TODO: Research option to provide fix instructions
	// result.Fixes = append(result.Fixes, sarif.NewFix().WithDescription(fmt.Sprintf("Was fixed with version %s")))

	ruleIdx := sr.getRule(vuln.OSV.ID)
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

func (sr *SarifReporter) generateRuleHelp(vuln *vulncheck.Vuln) (text string, markdown string) {
	fixVersion := sr.searchFixVersion(vuln.OSV.Affected)
	uri := fmt.Sprintf("https://pkg.go.dev/vuln/%s", vuln.OSV.ID)

	return fmt.Sprintf("Vulnerability %s \n Module: %s \n Package: %s \n Fixed in Version: %s \n", vuln.OSV.ID, vuln.ModPath, vuln.PkgPath, fixVersion),
		fmt.Sprintf("**Vulnerability [%s](%s)**\n%s\n| Module | Package | Fixed in Version |\n| --- | --- |:---:|\n|%s|%s|%s|\n", vuln.OSV.ID, uri, vuln.OSV.Details, vuln.ModPath, vuln.PkgPath, fixVersion)
}

func (sr *SarifReporter) generateResultMessage(vuln *vulncheck.Vuln, entry vulncheck.StackEntry, stack vulncheck.CallStack) (text string, markdown string) {
	relativeFile := sr.makePathRelative(entry.Call.Pos.String())
	linkToFile := fmt.Sprintf("https://github.com/%s/blob/main/%s#L%d", os.Getenv(envRepo), sr.makePathRelative(entry.Call.Pos.Filename), entry.Call.Pos.Line)
	linkToVuln := fmt.Sprintf("https://pkg.go.dev/vuln/%s", vuln.OSV.ID)

	var txtBuilder strings.Builder
	var markBuilder strings.Builder

	txtBuilder.WriteString(fmt.Sprintf("%s calls %s which has vulnerability %s\n",
		fmt.Sprintf("[%s] %s.%s", relativeFile, entry.Function.PkgPath, entry.Function.Name),
		fmt.Sprintf("%s.%s", vuln.PkgPath, entry.Call.Name),
		vuln.OSV.ID))
	txtBuilder.WriteString("Stacktrace: \n")

	markBuilder.WriteString(fmt.Sprintf("%s calls %s which has vulnerability [%s](%s)\n",
		fmt.Sprintf("[%s](%s) %s.%s", relativeFile, linkToFile, entry.Function.PkgPath, entry.Function.Name),
		fmt.Sprintf("%s.%s", vuln.PkgPath, entry.Call.Name),
		vuln.OSV.ID,
		linkToVuln,
	))

	markBuilder.WriteString("Stacktrace: \n")

	for _, line := range types.FormatCallStack(stack) {
		txtBuilder.WriteString(fmt.Sprintf("%s \n", line))
		markBuilder.WriteString(fmt.Sprintf("* %s \n", line))
	}

	return txtBuilder.String(), markBuilder.String()
}
