package main

import (
	"os"
	"runtime"

	"github.com/Templum/govulncheck-action/pkg/action"
	"github.com/Templum/govulncheck-action/pkg/github"
	"github.com/Templum/govulncheck-action/pkg/sarif"
	"github.com/Templum/govulncheck-action/pkg/vulncheck"
	"github.com/rs/zerolog"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: zerolog.TimeFormatUnix}).
		With().
		Timestamp().
		Logger() // Main Logger

	workDir, _ := os.Getwd()

	github := github.NewSarifUploader(logger)
	reporter := sarif.NewSarifReporter(logger, workDir)
	scanner := vulncheck.NewScanner(logger, workDir)
	processor := action.NewVulncheckProcessor(workDir)

	if os.Getenv("DEBUG") == "true" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		logger.Debug().Msg("Enabled Debug Level logs")
	}

	if os.Getenv("LOCAL") == "true" {
		scanner = vulncheck.NewLocalScanner(logger, "/workspaces/govulncheck-action/hack/found.json")
		logger.Debug().Msg("Enabled Local Development mode, scanner will return static result based on found.json")
	}

	logger.Info().
		Str("Go-Version", runtime.Version()).
		Str("Go-Os", runtime.GOOS).
		Str("Go-Arch", runtime.GOARCH).
		Msg("GoEnvironment Details:")

	logger.Debug().
		Str("Package", os.Getenv("PACKAGE")).
		Str("Fail on Vulnerabilities", os.Getenv("STRICT")).
		Msg("Action Inputs:")

	result, err := scanner.Scan()
	if err != nil {
		logger.Error().Err(err).Msg("Scanning yielded error")
		os.Exit(2)
	}

	vulnerableStacks := vulncheck.Resolve(result)
	vulnerableStacks = processor.RemoveDuplicates(vulnerableStacks)

	err = reporter.Convert(vulnerableStacks)
	if err != nil {
		logger.Error().Err(err).Msg("Conversion of Scan yielded error")
		os.Exit(2)
	}

	err = github.UploadReport(reporter)
	if err != nil {
		logger.Error().Err(err).Msg("Upload of Sarif Report GitHub yielded error")
		os.Exit(2)
	}

	logger.Info().Msg("Successfully uploaded Sarif Report to Github, it will be available after processing")

	if os.Getenv("STRICT") == "true" {
		logger.Debug().Msg("Action is running in strict mode")

		if len(vulnerableStacks) > 0 {
			logger.Info().Msg("Encountered at least one vulnerability while running in strict mode, will mark outcome as failed")
			os.Exit(2)
		}
	}

}
