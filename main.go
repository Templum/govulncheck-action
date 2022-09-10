package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"

	"github.com/Templum/govulncheck-action/pkg/sarif"
	"golang.org/x/vuln/vulncheck"
)

const (
	version = "latest" // TODO: Read from env. Needs to be numeric, hence if latest we need to guess it somehow
)

func main() {
	var result vulncheck.Result

	rawJson, err := os.ReadFile(path.Join("hack", "vuln_found.json"))
	if err != nil {
		fmt.Println("Failed to read vuln.json")
		os.Exit(1)
	}

	err = json.Unmarshal(rawJson, &result)

	if err != nil {
		fmt.Printf("Failed to parse vuln.json %v \n", err)
		os.Exit(1)
	}

	file, err := os.Create("report.sarif")
	if err != nil {
		fmt.Printf("Failed to create report.sarif %v \n", err)
		os.Exit(1)
	}

	defer file.Close()
	reporter := sarif.NewSarifReporter(file)
	err = reporter.Init()
	if err != nil {
		fmt.Printf("Failed to init sarif Reporter due to %v \n", err)
		os.Exit(1)
	}

	for _, current := range result.Vulns {
		reporter.AddRule(*current)

		reporter.AddResult(*current)
	}

	err = reporter.Flush()
	if err != nil {
		fmt.Printf("Failed to write sarif report due to %v \n", err)
		os.Exit(1)
	}

	fmt.Println("Succesfully scanned and created sarif report")
}
