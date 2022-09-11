package vulncheck

import (
	"fmt"
	"os"

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
					c.reporter.AddCallResult(current, call)
				}
			}
		}

	}

	fmt.Printf("Converted Report to Sarif format found %d Vulnerabilities\n", len(result.Vulns))
	return nil
}
