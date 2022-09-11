package vulncheck

import (
	"fmt"
	"os"
	"strings"

	"github.com/Templum/govulncheck-action/pkg/sarif"
	"golang.org/x/vuln/vulncheck"
)

type VulncheckConverter interface {
	Convert(result *vulncheck.Result) error
}

type Converter struct {
	reporter sarif.Reporter
}

func NewVulncheckConverter(reporter sarif.Reporter) VulncheckConverter {
	return &Converter{reporter: reporter}
}

func (c *Converter) getVulncheckVersion() string {
	specifiedVersion := os.Getenv("VERSION")

	return specifiedVersion
}

func (c *Converter) Convert(result *vulncheck.Result) error {
	localDir, _ := os.Getwd()

	err := c.reporter.CreateEmptyReport(c.getVulncheckVersion())
	if err != nil {
		return err
	}

	for _, current := range result.Vulns {
		c.reporter.AddRule(*current)

		if current.CallSink == 0 {
			if len(result.Imports.Packages) >= current.ImportSink {
				c.reporter.AddImportResult(current, result.Imports.Packages[current.ImportSink])
			}
		} else {
			if len(result.Calls.Functions) >= current.CallSink {
				for _, call := range result.Calls.Functions[current.CallSink].CallSites {
					// Only reporting code that is used
					if strings.Contains(call.Pos.Filename, localDir) {

						call.Pos.Filename = makePathRelative(call.Pos.Filename, localDir)
						c.reporter.AddCallResult(current, call)
					}
				}
			}
		}

	}

	fmt.Println("Converted Report to Sarif format")
	return nil
}

func makePathRelative(absolute string, workdir string) string {
	return strings.Replace(absolute, workdir, "", 1)
}
