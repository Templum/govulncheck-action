package vulncheck

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Templum/govulncheck-action/pkg/sarif"
	"golang.org/x/vuln/vulncheck"
)

type Converter struct {
	reporter *sarif.SarifReporter
}

func NewVulncheckConverter(reporter *sarif.SarifReporter) *Converter {
	return &Converter{reporter: reporter}
}

func (c *Converter) ReadJsonReport(path string) (*vulncheck.Result, error) {
	rawJson, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("was not able to read vulncheck report located at %s", path)
	}

	var result vulncheck.Result
	err = json.Unmarshal(rawJson, &result)
	if err != nil {
		return nil, fmt.Errorf("failed parsing result failed with %v", err)
	}

	fmt.Printf("Successfully read report from %s\n", path)
	return &result, nil
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
			if len(result.Imports.Packages) <= current.ImportSink {
				c.reporter.AddImportResult(current, result.Imports.Packages[current.ImportSink])
			}
		} else {
			if len(result.Calls.Functions) == current.CallSink {
				for _, call := range result.Calls.Functions[current.CallSink].CallSites {
					c.reporter.AddCallResult(current, call)
				}
			}
		}

	}

	fmt.Printf("Converted Report to Sarif format found %d Vulnerabilities\n", len(result.Vulns))
	return nil
}
