package sarif

import (
	"bytes"
	"encoding/json"
	"io"
	"path"
	"testing"

	"github.com/Templum/govulncheck-action/pkg/types"
	helper "github.com/Templum/govulncheck-action/pkg/vulncheck"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestSarifReporter_Convert(t *testing.T) {
	scanner := helper.NewLocalScanner(zerolog.Nop(), path.Join("..", "..", "hack", "found.json"))
	result, _ := scanner.Scan()

	t.Run("Should convert a preprocessed report into sarif format", func(t *testing.T) {
		target := NewSarifReporter(zerolog.Nop(), "/workspaces/govulncheck-action")
		ref := target.(*SarifReporter)

		_ = target.Convert(result)

		assert.NotNil(t, ref.report, "should have create an empty report")
		assert.NotNil(t, ref.run, "should have filled a run with details")

		assert.Equal(t, len(ref.run.Results), 9, "example report should have 9 calls to vulnerabilities")
		assert.Equal(t, len(ref.run.Tool.Driver.Rules), 9, "example report should have 9 vulnerabilities")
		assert.Equal(t, len(ref.report.Runs), 0, "should have not yet added the run to the report")
	})

	t.Run("Should create a empty report if nothing was found", func(t *testing.T) {
		target := NewSarifReporter(zerolog.Nop(), "/workspaces/govulncheck-action")
		ref := target.(*SarifReporter)

		_ = target.Convert(&types.Result{Vulns: []types.Vulns{}})

		assert.NotNil(t, ref.report, "should have create an empty report")
		assert.NotNil(t, ref.run, "should have filled a run with details")

		assert.GreaterOrEqual(t, len(ref.run.Results), 0, "should not find call sites in an empty report")
		assert.GreaterOrEqual(t, len(ref.run.Tool.Driver.Rules), 0, "should not find vulnerabilities in an empty report")
		assert.Equal(t, len(ref.report.Runs), 0, "should have not yet added the run to the report")
	})
}

func TestSarifReporter_Write(t *testing.T) {
	t.Run("should add the run to the report before writing it", func(t *testing.T) {
		target := NewSarifReporter(zerolog.Nop(), "/workspaces/govulncheck-action")
		ref := target.(*SarifReporter)
		ref.createEmptyReport("")

		assert.NotNil(t, ref.report, "should have create an empty report")
		assert.NotNil(t, ref.run, "should have filled a run with details")
		assert.Equal(t, len(ref.report.Runs), 0, "should have not yet added the run to the report")

		_ = target.Write(io.Discard)
		assert.Equal(t, len(ref.report.Runs), 1, "should have added the run during the write")
	})

	t.Run("should write the report and run to the provided writer", func(t *testing.T) {
		target := NewSarifReporter(zerolog.Nop(), "/workspaces/govulncheck-action")
		ref := target.(*SarifReporter)
		ref.createEmptyReport("")

		var writer bytes.Buffer

		_ = target.Write(&writer)

		assert.Greater(t, writer.Len(), 0, "should have written something to writer")
		var report *sarif.Report

		err := json.Unmarshal(writer.Bytes(), &report)

		assert.Nil(t, err, "should be able to parse write output back into a sarif report")
	})
}
