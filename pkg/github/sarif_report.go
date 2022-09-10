package github

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/Templum/govulncheck-action/pkg/sarif"
	"github.com/google/go-github/v47/github"
	"golang.org/x/oauth2"
)

const (
	envOwner  = "GITHUB_REPOSITORY_OWNER"
	envRepo   = "GITHUB_REPOSITORY"
	envGitRef = "GITHUB_REF"
	envSha    = "GITHUB_SHA"
	envToken  = "GITHUB_TOKEN"
)

type GithubResultUploader struct {
	client *github.Client
}

func NewGithubGithubResultUploader() *GithubResultUploader {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv(envToken)},
	)
	tc := oauth2.NewClient(ctx, ts)

	return &GithubResultUploader{client: github.NewClient(tc)}
}

func (g *GithubResultUploader) UploadReport(reporter *sarif.SarifReporter) error {
	owner := os.Getenv(envOwner)
	repo := os.Getenv(envRepo)
	commit := os.Getenv(envSha)
	gitRef := os.Getenv(envGitRef)

	encodedAndCompressedReport, err := g.prepareReport(reporter)
	if err != nil {
		return err
	}

	_, _, err = g.client.CodeScanning.UploadSarif(context.Background(), owner, repo, &github.SarifAnalysis{
		CommitSHA: &commit,
		Ref:       &gitRef,
		Sarif:     &encodedAndCompressedReport,
	})
	if err != nil {
		return err
	}

	return nil
}

func (g *GithubResultUploader) prepareReport(reporter *sarif.SarifReporter) (string, error) {
	buf := bytes.NewBufferString("")
	wr, err := gzip.NewWriterLevel(buf, flate.BestSpeed)
	if err != nil {
		return "", err
	}

	err = reporter.Flush(wr)
	if err != nil {
		return "", err
	}

	fmt.Println("Debug", buf.String())
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
