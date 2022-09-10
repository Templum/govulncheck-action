package main

import (
	"fmt"
	"os"

	"github.com/Templum/govulncheck-action/pkg/sarif"
	"github.com/Templum/govulncheck-action/pkg/vulncheck"
)

func main() {
	reporter := sarif.NewSarifReporter()
	converter := vulncheck.NewVulncheckConverter(reporter)

	result, err := converter.ReadJsonReport("/tmp/vulncheck.json")
	if err != nil {
		fmt.Println(err) // TODO: Start using proper logger
		os.Exit(2)
	}

	err = converter.Convert(result)
	if err != nil {
		fmt.Println(err) // TODO: Start using proper logger
		os.Exit(2)
	}

	err = converter.FlushToFile("report.sarif")
	if err != nil {
		fmt.Println(err) // TODO: Start using proper logger
		os.Exit(2)
	}

	// TODO: Implement upload to Github using the API
	fmt.Println("Successfully processed vulncheck report and generated report.sarif for upload")
}
