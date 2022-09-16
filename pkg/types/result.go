package types

import "golang.org/x/vuln/vulncheck"

type VulnerableStacks map[*vulncheck.Vuln][]vulncheck.CallStack
