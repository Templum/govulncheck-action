package main

import (
	"os"
	"runtime"

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

	reporter := sarif.NewSarifReporter(logger)
	github := github.NewSarifUploader(logger)
	scanner := vulncheck.NewScanner(logger)

	if os.Getenv("DEBUG") == "true" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		logger.Debug().Msg("Running in Debug-Mode will use hardcoded scan result and enable debug logs")

		scanner = vulncheck.NewLocalScanner(logger, "/workspaces/govulncheck-action/hack/output.json")
	}

	logger.Info().
		Str("Go-Version", runtime.Version()).
		Str("Go-Os", runtime.GOOS).
		Str("Go-Arch", runtime.GOARCH).
		Msg("GoEnvironment Details:")

	result, err := scanner.Scan()
	if err != nil {
		logger.Error().Err(err).Msg("Scanning yielded error")
		os.Exit(2)
	}

	err = reporter.Convert(result)
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
}
