package action

import (
	"go/token"
	"path"
	"testing"

	"github.com/Templum/govulncheck-action/pkg/types"
	helper "github.com/Templum/govulncheck-action/pkg/vulncheck"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"golang.org/x/vuln/vulncheck"
)

func TestFindVulnerableCallSite(t *testing.T) {
	userCallSite := vulncheck.StackEntry{
		Function: &vulncheck.FuncNode{
			ID:       2,
			Name:     "Testcase",
			RecvType: "",
			PkgPath:  "github.com/Templum/playground/pkg/json",
			Pos: &token.Position{
				Filename: "/workspaces/unit/pkg/json/testcase.go",
				Offset:   130,
				Line:     10,
				Column:   6,
			},
			CallSites: []*vulncheck.CallSite{}, // Not needed for this function
		},
		Call: &vulncheck.CallSite{
			Parent:   2,
			Name:     "Get",
			RecvType: "",
			Resolved: true,
			Pos: &token.Position{
				Filename: "/workspaces/unit/pkg/json/testcase.go",
				Offset:   162,
				Line:     11,
				Column:   20,
			},
		},
	}

	stack := []vulncheck.StackEntry{
		userCallSite,
		{
			Function: &vulncheck.FuncNode{
				ID:       12,
				Name:     "Get",
				RecvType: "",
				PkgPath:  "github.com/tidwall/gjson",
				Pos: &token.Position{
					Filename: "/go/pkg/mod/github.com/tidwall/gjson@v1.6.4/gjson.go",
					Offset:   37859,
					Line:     1873,
					Column:   6,
				},
				CallSites: []*vulncheck.CallSite{}, // Not needed for this function
			},
			Call: &vulncheck.CallSite{
				Parent:   12,
				Name:     "parseObject",
				RecvType: "",
				Resolved: true,
				Pos: &token.Position{
					Filename: "/go/pkg/mod/github.com/tidwall/gjson@v1.6.4/gjson.go",
					Offset:   39894,
					Line:     1963,
					Column:   16,
				},
			},
		},
		{
			Function: &vulncheck.FuncNode{
				ID:       16,
				Name:     "parseObject",
				RecvType: "",
				PkgPath:  "github.com/tidwall/gjson",
				Pos: &token.Position{
					Filename: "/go/pkg/mod/github.com/tidwall/gjson@v1.6.4/gjson.go",
					Offset:   21927,
					Line:     1114,
					Column:   2,
				},
				CallSites: []*vulncheck.CallSite{}, // Not needed for this function
			},
			Call: nil,
		}, // Vulnerability
	}

	t.Run("should return empty entry if nothing is found", func(t *testing.T) {
		callSite := FindVulnerableCallSite("/workspaces/other", stack)

		assert.Nil(t, callSite.Call, "should have no call")
		assert.Nil(t, callSite.Function, "should have no function")
	})

	t.Run("should return first calling site located in user code", func(t *testing.T) {
		callSite := FindVulnerableCallSite("/workspaces/unit", stack)

		assert.NotNil(t, callSite.Call, "should have a call")
		assert.NotNil(t, callSite.Function, "should have a function")
		assert.Equal(t, userCallSite, callSite, "should find the correct call site")
	})
}

func CalculateTotalFindings(input types.VulnerableStacks) int {
	output := 0

	for _, findings := range input {
		output += len(findings)
	}

	return output
}

func TestVulncheckProcessor_RemoveDuplicates(t *testing.T) {
	scanner := helper.NewLocalScanner(zerolog.Nop(), path.Join("..", "..", "hack", "found.json"))
	result, _ := scanner.Scan()
	input := helper.Resolve(result)

	hasDuplicateCallsites := make(types.VulnerableStacks)
	hasDuplicateVuln := make(types.VulnerableStacks)

	for key, value := range input {
		if key.OSV.ID == "GO-2021-0113" {
			hasDuplicateVuln[key] = value
		}

		if key.OSV.ID == "GO-2021-0061" && key.Symbol == "decoder.unmarshal" {
			hasDuplicateCallsites[key] = value
		}
	}

	t.Run("should remove duplicates which are called from the same site", func(t *testing.T) {
		target := NewVulncheckProcessor()
		target.workDir = "/workspaces/govulncheck-action"

		reduced := target.RemoveDuplicates(hasDuplicateCallsites)

		assert.NotNil(t, reduced, "should not be nil")
		assert.Equal(t, len(reduced), len(hasDuplicateCallsites), "should have same amount of entries")
		assert.Less(t, CalculateTotalFindings(reduced), CalculateTotalFindings(hasDuplicateCallsites), "reduced should be less after removal of duplicates")
	})

	t.Run("should remove duplicates which are for the same vulnerability", func(t *testing.T) {
		target := NewVulncheckProcessor()
		target.workDir = "/workspaces/govulncheck-action"

		reduced := target.RemoveDuplicates(hasDuplicateVuln)

		assert.NotNil(t, reduced, "should not be nil")
		assert.Less(t, len(reduced), len(hasDuplicateVuln), "should only have one entry now")
		assert.Less(t, CalculateTotalFindings(reduced), CalculateTotalFindings(hasDuplicateVuln), "reduced should be less after removal of duplicates")
	})
}
