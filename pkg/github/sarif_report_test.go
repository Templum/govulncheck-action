package github

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/Templum/govulncheck-action/pkg/types"
	"github.com/google/go-github/v47/github"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

type MockReport struct{ fail bool }

func NewMockReport(shouldFail bool) types.Reporter {
	return &MockReport{fail: shouldFail}
}

func (m *MockReport) Convert(result types.VulnerableStacks) error {
	return nil
}

func (m *MockReport) Write(dest io.Writer) error {
	if m.fail {
		return errors.New("version [1.1.1] is not supported")
	}

	emptyReport, _ := sarif.New(sarif.Version210)
	run := sarif.NewRunWithInformationURI("govulncheck", "")
	run.Tool.Driver.WithVersion("0.0.1")
	run.Tool.Driver.WithFullName("govulncheck")
	run.ColumnKind = "utf16CodeUnits"
	emptyReport.AddRun(run)

	return emptyReport.Write(dest)
}

func ExtractSarifString(body io.ReadCloser) ([]byte, error) {
	request, _ := io.ReadAll(body)
	var report github.SarifAnalysis

	err := json.Unmarshal(request, &report)
	if err != nil {
		return []byte{}, err
	}

	return []byte(*report.Sarif), nil
}

func DecodeSarifString(base64String []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(base64String))
}

func DecompressSarifString(compressedString []byte) ([]byte, error) {
	buffered := bytes.NewBuffer(compressedString)
	gzipReader, _ := gzip.NewReader(buffered)
	decompressed, err := io.ReadAll(gzipReader)

	if err != nil {
		return []byte{}, err
	}
	return decompressed, err
}

func TestMain(m *testing.M) {
	os.Setenv("GITHUB_REPOSITORY", "Templum/playground")
	os.Setenv("GITHUB_REF", "refs/heads/unit")
	os.Setenv("GITHUB_SHA", "ffac537e6cbbf934b08745a378932722df287a53")
	os.Setenv("GITHUB_TOKEN", "Token")

	exitVal := m.Run()

	os.Unsetenv("GITHUB_REPOSITORY")
	os.Unsetenv("GITHUB_REF")
	os.Unsetenv("GITHUB_SHA")
	os.Unsetenv("GITHUB_TOKEN")

	os.Exit(exitVal)
}

func TestGithubSarifUploader_UploadReport(t *testing.T) {
	uploadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base64String, err := ExtractSarifString(r.Body)
		if err != nil {
			t.Errorf("Extracting Sarif String failed with %v", err)
		}

		compressedString, err := DecodeSarifString(base64String)
		if err != nil {
			t.Errorf("Decoding Sarif String failed with %v", err)
		}

		sarifReport, err := DecompressSarifString(compressedString)
		if err != nil {
			t.Errorf("Decompressing Sarif String failed with %v", err)
		}

		if !strings.HasPrefix(string(sarifReport), "{\"version\":\"2.1.0\",\"$schema\":\"https://json.schemastore.org/sarif-2.1.0-rtm.5.json\"") {
			t.Error("Sarif Report did not start as expected")
		}

		response := github.SarifID{
			ID:  github.String("0f971e9e-36d1-11ed-9b72-683377ed374"),
			URL: github.String("https://api.github.com/repos/Templum/unit/code-scanning/analyses/43004097"),
		}
		out, _ := json.Marshal(response)
		w.WriteHeader(202)
		_, _ = w.Write(out)
	}))
	uploadUrl, _ := url.Parse(fmt.Sprintf("%s/", uploadServer.URL))
	defer uploadServer.Close()

	unreachableServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502)
		_, _ = w.Write([]byte{})
	}))

	unreachableUrl, _ := url.Parse(fmt.Sprintf("%s/", unreachableServer.URL))
	defer unreachableServer.Close()

	t.Run("should upload report as gzip compressed base64", func(t *testing.T) {
		target := NewSarifUploader(zerolog.Nop())
		ref := target.(*GithubSarifUploader)
		ref.client = github.NewClient(uploadServer.Client())
		ref.client.BaseURL = uploadUrl

		err := target.UploadReport(NewMockReport(false))
		assert.Nil(t, err, "should not fail")
	})

	t.Run("should return error if status code is not 202", func(t *testing.T) {
		target := NewSarifUploader(zerolog.Nop())
		ref := target.(*GithubSarifUploader)
		ref.client = github.NewClient(unreachableServer.Client())
		ref.client.BaseURL = unreachableUrl

		err := target.UploadReport(NewMockReport(false))
		assert.NotNil(t, err, "should fail")
		assert.Contains(t, err.Error(), "502")
	})

	t.Run("should return received error if report writing fails", func(t *testing.T) {
		target := NewSarifUploader(zerolog.Nop())

		err := target.UploadReport(NewMockReport(true))
		assert.NotNil(t, err, "should fail")
		assert.Contains(t, err.Error(), "version [1.1.1] is not supported")
	})
}
