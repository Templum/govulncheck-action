package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Templum/govulncheck-action/pkg/github"
	"github.com/Templum/govulncheck-action/pkg/sarif"
	"github.com/Templum/govulncheck-action/pkg/vulncheck"
)

func main() {
	reporter := sarif.NewSarifReporter()
	converter := vulncheck.NewVulncheckConverter(reporter)
	github := github.NewGithubGithubResultUploader()

	path := "/tmp/vulncheck.json"

	if os.Getenv("LOCAL") == "true" {
		path = filepath.Join("hack", "multi.json")
	}

	result, err := converter.ReadJsonReport(path)
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
