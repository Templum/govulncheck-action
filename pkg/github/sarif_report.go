package github

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/Templum/govulncheck-action/pkg/types"
	"github.com/google/go-github/v47/github"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

const (
	envRepo   = "GITHUB_REPOSITORY"
	envGitRef = "GITHUB_REF"
	envSha    = "GITHUB_SHA"
	envToken  = "GITHUB_TOKEN"
)

type SarifUploader interface {
	UploadReport(report types.Reporter) error
}

type GithubSarifUploader struct {
	client *github.Client
	log    zerolog.Logger
}

func NewSarifUploader(logger zerolog.Logger) SarifUploader {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv(envToken)},
	)
	tc := oauth2.NewClient(ctx, ts)

	return &GithubSarifUploader{client: github.NewClient(tc), log: logger}
}

func (g *GithubSarifUploader) UploadReport(report types.Reporter) error {
	ownerAndRepo := strings.Split(os.Getenv(envRepo), "/")
	commit := os.Getenv(envSha)
	gitRef := os.Getenv(envGitRef)

	g.log.Info().
		Str("Commit", commit).
		Str("Ref", gitRef).
		Msg("Preparing Report for upload to Github")

	encodedAndCompressedReport, err := g.prepareReport(report)
	if err != nil {
		return err
	}

	_, _, err = g.client.CodeScanning.UploadSarif(context.Background(), ownerAndRepo[0], ownerAndRepo[1], &github.SarifAnalysis{
		CommitSHA: &commit,
		Ref:       &gitRef,
		Sarif:     &encodedAndCompressedReport,
	})

	if _, ok := err.(*github.AcceptedError); ok {
		var response github.SarifID
		_ = json.Unmarshal(err.(*github.AcceptedError).Raw, &response)

		g.log.Info().
			Str("sarif_id", *response.ID).
			Msg("Report was uploaded to GitHub")
		return nil
	}

	if err != nil {
		return err
	}

	return errors.New("unexpected response from github")
}

func (g *GithubSarifUploader) prepareReport(report types.Reporter) (string, error) {
	var b bytes.Buffer

	// Can only throw for invalid level, which can not be the case here
	writer, _ := gzip.NewWriterLevel(&b, flate.BestSpeed)

	err := report.Write(writer)
	if err != nil {
		return "", err
	}

	// Only through calling close the bytes will be written to the underlying writer
	err = writer.Close()
	if err != nil {
		return "", err
	}

	g.log.Debug().
		Int("Original Size", b.Len()).
		Int("Compressed Size", b.Cap()).
		Msg("Report was successfully gzipped")

	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}
