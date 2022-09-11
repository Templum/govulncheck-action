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

type SarifUploader interface {
	UploadReport(report sarif.Report) error
}

type GithubSarifUploader struct {
	client *github.Client
}

func NewSarifUploader() SarifUploader {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: os.Getenv(envToken)},
	)
	tc := oauth2.NewClient(ctx, ts)

	return &GithubSarifUploader{client: github.NewClient(tc)}
}

func (g *GithubSarifUploader) UploadReport(report sarif.Report) error {
	ownerAndRepo := strings.Split(os.Getenv(envRepo), "/")
	commit := os.Getenv(envSha)
	gitRef := os.Getenv(envGitRef)

	fmt.Printf("Preparing Report for commit %s on ref %s \n", commit, gitRef)
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

		fmt.Printf("Successfully uploaded Report to Github it received ID %s \n", *response.ID)
		return nil
	}

	if err != nil {
		return err
	}

	return errors.New("unexpected response from github")
}

func (g *GithubSarifUploader) prepareReport(report sarif.Report) (string, error) {
	var b bytes.Buffer

	// Can only throw for invalid level, which can not be the case here
	writer, _ := gzip.NewWriterLevel(&b, flate.BestSpeed)

	err := report.Flush(writer)
	if err != nil {
		return "", err
	}

	// Only through calling close the bytes will be written to the underlying writer
	err = writer.Close()
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
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
