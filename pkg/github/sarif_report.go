package github

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Templum/govulncheck-action/pkg/sarif"
	"github.com/google/go-github/v47/github"
	"golang.org/x/oauth2"
)

const (
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
	ownerAndRepo := strings.Split(os.Getenv(envRepo), "/")
	commit := os.Getenv(envSha)
	gitRef := os.Getenv(envGitRef)

	fmt.Printf("Preparing Report for commit %s on ref %s \n", commit, gitRef)
	encodedAndCompressedReport, err := g.prepareReport(reporter)
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

		fmt.Printf("Successfully uploaded Report to Github it received ID %s \n", *response.ID)
		return nil
	}

	if err != nil {
		return err
	}

	return errors.New("unexpected response from github")
}

func (g *GithubResultUploader) prepareReport(reporter *sarif.SarifReporter) (string, error) {
	var b bytes.Buffer

	writer, err := gzip.NewWriterLevel(&b, flate.BestSpeed)
	if err != nil {
		return "", err
	}

	err = reporter.Flush(writer)
	if err != nil {
		return "", err
	}

	err = writer.Close()
	if err != nil {
		return "", err
	}

	writtenBytes := b.Bytes()
	return base64.StdEncoding.EncodeToString(writtenBytes), nil
}

/**
func debugCompressedContent(raw []byte) {
	var readB = bytes.NewBuffer(raw)

	reader, _ := gzip.NewReader(readB)
	b, err := io.ReadAll(reader)
	if err != nil {
		fmt.Printf("Error %v", err)
	} else {
		fmt.Printf("Decoded string %s", string(b))
	}
}
**/
