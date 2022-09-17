package action

import (
	"go/token"
	"testing"

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

func TestVulncheckProcessor_RemoveDuplicates(t *testing.T) {

}
