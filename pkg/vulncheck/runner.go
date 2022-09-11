package vulncheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/vuln/vulncheck"
)

const (
	command    = "govulncheck"
	flag       = "-json"
	envPackage = "PACKAGE"
)

type Scanner interface {
	Scan() (*vulncheck.Result, error)
}

type CmdScanner struct {
}

func NewScanner() Scanner {
	return &CmdScanner{}
}

func (r *CmdScanner) Scan() (*vulncheck.Result, error) {
	pkg := os.Getenv(envPackage)
	out, cmdErr := exec.Command("govulncheck", "-json", pkg).Output()

	if err, ok := cmdErr.(*exec.ExitError); ok {
		if err.ExitCode() > 0 {
			println("Scan found vulnerabilities in codebase")
		} else {
			println("Scan did not find any vulnerabilities in codebase")
		}

	}

	var result vulncheck.Result
	err := json.Unmarshal(out, &result)
	if err != nil {
		return nil, errors.New("scan failed to produce proper report")
	}

	fmt.Println("Successfully parsed report")
	return &result, nil
}
