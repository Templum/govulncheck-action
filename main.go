package main

import (
	"fmt"
	"os"

	"github.com/Templum/govulncheck-action/pkg/github"
	"github.com/Templum/govulncheck-action/pkg/sarif"
	"github.com/Templum/govulncheck-action/pkg/vulncheck"
)

func main() {
	reporter := sarif.NewSarifReporter()
	converter := vulncheck.NewVulncheckConverter(reporter)
	github := github.NewGithubGithubResultUploader()

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

	err = github.UploadReport(reporter)
	if err != nil {
		fmt.Println(err) // TODO: Start using proper logger
		os.Exit(2)
	}

	fmt.Println("Successfully processed uploaded vulncheck report to Github")
}
