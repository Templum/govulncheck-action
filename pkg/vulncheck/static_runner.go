package vulncheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/vuln/vulncheck"
)

type StaticScanner struct {
}

func NewLocalScanner() Scanner {
	return &StaticScanner{}
}

func (r *StaticScanner) Scan() (*vulncheck.Result, error) {
	out, _ := os.ReadFile("/workspaces/govulncheck-action/hack/found.json")

	var result vulncheck.Result
	err := json.Unmarshal(out, &result)
	if err != nil {
		return nil, errors.New("scan failed to produce proper report")
	}

	fmt.Println("Successfully parsed report")
	return &result, nil
}
