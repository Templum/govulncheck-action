package action

import (
	"strings"

	"github.com/Templum/govulncheck-action/pkg/types"
	"github.com/rs/zerolog/log"
	"golang.org/x/vuln/vulncheck"
)

type VulncheckProcessor struct {
	workDir string
}

func NewVulncheckProcessor(workDir string) *VulncheckProcessor {
	return &VulncheckProcessor{
		workDir: workDir,
	}
}

func (p *VulncheckProcessor) RemoveDuplicates(vulnerableStacks types.VulnerableStacks) types.VulnerableStacks {
	// Will hold all unique items and there stacks
	uniqueVulnStacks := make(types.VulnerableStacks)
	// Sometimes vulnerabilities are included for each affected symbol
	lookupTable := make(map[string]map[string]bool)

	for vuln, stacks := range vulnerableStacks {
		ref := findRef(vuln.OSV.ID, uniqueVulnStacks)
		if ref == nil {
			uniqueVulnStacks[vuln] = make([]vulncheck.CallStack, 0)
			ref = vuln
		}

		if _, ok := lookupTable[vuln.OSV.ID]; !ok {
			lookupTable[vuln.OSV.ID] = make(map[string]bool)
		}

		for _, current := range stacks {
			entry := FindVulnerableCallSite(p.workDir, current)

			if entry.Function != nil && entry.Call != nil {
				callLocation := entry.Call.Pos.String()

				if _, ok := lookupTable[vuln.OSV.ID][callLocation]; !ok {
					lookupTable[vuln.OSV.ID][callLocation] = true
					uniqueVulnStacks[ref] = append(uniqueVulnStacks[ref], current)
				}
			}

		}
	}

	return uniqueVulnStacks
}

func FindVulnerableCallSite(workDir string, stack vulncheck.CallStack) vulncheck.StackEntry {
	// We start from the back as that is the entrypoint for the reported vulnerability
	for i := range stack {
		current := stack[len(stack)-1-i]

		if current.Call != nil {
			log.Debug().Bool("Contains", strings.Contains(current.Call.Pos.Filename, workDir)).Msgf("Filename %s Workspace %s", current.Call.Pos.Filename, workDir)
			if strings.Contains(current.Call.Pos.Filename, workDir) {
				return current
			}
		}
	}

	return vulncheck.StackEntry{Function: nil, Call: nil}
}

func findRef(osvID string, lookup types.VulnerableStacks) *vulncheck.Vuln {
	for key := range lookup {
		if key.OSV.ID == osvID {
			return key
		}
	}

	return nil
}
