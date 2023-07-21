package sarif

import (
	"fmt"
	"io"
	"strings"

	"github.com/Templum/govulncheck-action/pkg/types"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/rs/zerolog"
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

func (sr *SarifReporter) Convert(report *types.Report) error {
	sr.createEmptyReport(report.Version)

	sr.log.Debug().Int("Number of Call Sites", len(report.Findings)).Msgf("Scan result shows the code is affected by %d vulnerabilities", len(report.Vulnerabilities))

	for _, vuln := range report.Vulnerabilities {
		sr.addRule(vuln)
	}

	for _, finding := range report.Findings {

		if len(finding.Trace) > 1 {
			sr.addDirectCallResult(finding)
		} else {
			sr.addImportResult(finding)
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
	run.Tool.Driver.WithVersion(vulncheckVersion)
	run.Tool.Driver.WithFullName(fullName)
	run.ColumnKind = "utf16CodeUnits"

	sr.report = report
	sr.run = run
}

func (sr *SarifReporter) addRule(vuln types.Entry) {
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

func (sr *SarifReporter) addDirectCallResult(finding types.Finding) {
	callSite := sr.extractCallSite(finding.Trace)
	indirectCaller := sr.extractIndirectCaller(finding.Trace)
	vulnerableSymbol := sr.extractVulnerableSymbol(finding.Trace)

	result := sarif.NewRuleResult(finding.OSV).
		WithLevel(severity).
		WithMessage(sarif.NewMessage().WithText(sr.generateCallSummary(callSite, indirectCaller, vulnerableSymbol)))

	sr.log.Debug().
		Str("Symbol", fmt.Sprintf("%s.%s", vulnerableSymbol.Package, vulnerableSymbol.Function)).
		Msgf("Adding a result for %s called from %s:%d:%d", finding.OSV, sr.makePathRelative(callSite.Position.Filename), callSite.Position.Line, callSite.Position.Column)

	region := sarif.NewRegion().
		WithStartLine(callSite.Position.Line).
		WithEndLine(callSite.Position.Line).
		WithStartColumn(callSite.Position.Column).
		WithEndColumn(callSite.Position.Column).
		WithCharOffset(callSite.Position.Offset)

	location := sarif.NewPhysicalLocation().
		WithArtifactLocation(sarif.NewSimpleArtifactLocation(sr.makePathRelative(callSite.Position.Filename)).WithUriBaseId(baseURI)).
		WithRegion(region)

	result.WithLocations([]*sarif.Location{sarif.NewLocationWithPhysicalLocation(location)})

	if ruleIdx := sr.getRule(finding.OSV); ruleIdx >= 0 {
		result.WithRuleIndex(ruleIdx)
		sr.run.AddResult(result)
	}
}

func (sr *SarifReporter) addImportResult(finding types.Finding) {
	vulnerableSymbol := finding.Trace[0]

	message := fmt.Sprintf("Package %s is vulnerable to %s, but there are no call stacks leading to the use of these vulnerabilities. You may not need to take any action.", vulnerableSymbol.Package, finding.OSV)

	result := sarif.NewRuleResult(finding.OSV).
		WithLevel(severity).
		WithMessage(sarif.NewMessage().WithText(message).WithMarkdown(message))

	sr.log.Debug().
		Str("Path", vulnerableSymbol.Package).
		Msgf("Adding a result related to an import exposed to %s", finding.OSV)

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

	if ruleIdx := sr.getRule(finding.OSV); ruleIdx >= 0 {
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
	relative := strings.ReplaceAll(absolute, sr.workDir, "")
	return strings.TrimPrefix(relative, "/")
}

func (sr *SarifReporter) searchFixVersion(versions []types.Affected) string {
	// Maybe in the future we can return all fixedVersions, so user can look for a version closer to his semver
	lastFix := "None"

	for _, current := range versions {
		for _, r := range current.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					lastFix = ev.Fixed
				}
			}
		}
	}

	return lastFix
}

func (sr *SarifReporter) searchPackage(versions []types.Affected) string {
	for _, current := range versions {
		return current.Module.Path
	}

	return "N/A"
}

func (sr *SarifReporter) generateRuleHelp(vuln types.Entry) (text string, markdown string) {
	fixVersion := sr.searchFixVersion(vuln.Affected)
	pkg := sr.searchPackage(vuln.Affected)

	uri := fmt.Sprintf("https://pkg.go.dev/vuln/%s", vuln.ID)

	return fmt.Sprintf("Vulnerability %s \n Package: %s \n Fixed in Version: %s \n", vuln.ID, pkg, fixVersion),
		fmt.Sprintf("**Vulnerability [%s](%s)**\n%s\n| Package | Fixed in Version |\n| --- |:---:|\n|%s|%s|\n", vuln.ID, uri, vuln.Details, pkg, fixVersion)
}

// extractCallSite will go over the provided call stack and extract the call site.
// As the call stack starts with the vulnerable symbol and moves towards the users code the last call
// is where the user calls the vulnerable code (either direct or indirect)
func (sr *SarifReporter) extractCallSite(callStack []*types.Frame) *types.Frame {
	return callStack[len(callStack)-1]
}

// extractIndirectCaller will go over the provided call stack and extract the indirect call site.
// This will be nil if the call site is directly calling the vulnerable code. In other cases it
// will be the code that is directly called by the user and eventually ends up calling the vulnerable code
func (sr *SarifReporter) extractIndirectCaller(callStack []*types.Frame) *types.Frame {
	if len(callStack) > 2 {
		return callStack[len(callStack)-2]
	}

	return nil
}

// extractVulnerableSymbol will return the first element of the provided call stack. Following the
// assumption that the call stack starts from the vulnerable code and moves towards the call site
func (sr *SarifReporter) extractVulnerableSymbol(callStack []*types.Frame) *types.Frame {
	return callStack[0]
}

func (sr *SarifReporter) generateCallSummary(callSite *types.Frame, indirectCaller *types.Frame, vulnerableSymbol *types.Frame) string {
	callingLocation := fmt.Sprintf("%s:%d:%d", sr.makePathRelative(callSite.Position.Filename), callSite.Position.Line, callSite.Position.Column)
	callingCode := fmt.Sprintf("%s.%s", callSite.Package, callSite.Function)

	var vulnerableCode string

	if vulnerableSymbol.Receiver == "" {
		vulnerableCode = fmt.Sprintf("%s.%s", vulnerableSymbol.Package, vulnerableSymbol.Function)
	} else {
		vulnerableCode = fmt.Sprintf("%s.%s.%s", vulnerableSymbol.Package, strings.TrimPrefix(vulnerableSymbol.Receiver, "*"), vulnerableSymbol.Function)
	}

	if indirectCaller != nil {
		indirectCalledCode := fmt.Sprintf("%s.%s", indirectCaller.Package, indirectCaller.Function)
		return fmt.Sprintf("%s: %s calls %s, which eventually calls %s", callingLocation, callingCode, indirectCalledCode, vulnerableCode)
	}

	return fmt.Sprintf("%s: %s calls %s", callingLocation, callingCode, vulnerableCode)
}
