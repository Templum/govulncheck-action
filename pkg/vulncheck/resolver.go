package vulncheck

import (
	"container/list"
	"sort"
	"strings"
	"sync"

	"github.com/Templum/govulncheck-action/pkg/types"
	"golang.org/x/vuln/vulncheck"
)

// Resolve is based on code from the vuln package, which is released under BSD-style license: https://github.com/golang/vuln/blob/cac67f5c7c815b458cf683c41541d157d8217beb/vulncheck/witness.go#L146-L168
// Resolve will collect all callstacks related to a vulnerability
// This occurs in parallel with one goroutine per vulnerability
func Resolve(result *vulncheck.Result) types.VulnerableStacks {
	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)
	vulnLookup := make(types.VulnerableStacks)
	for _, current := range result.Vulns {
		wg.Add(1)
		go func(vulnerability *vulncheck.Vuln) {
			var cs []vulncheck.CallStack
			if vulnerability.CallSink != 0 {
				cs = resolveCallstacks(vulnerability.CallSink, result)
			}

			// sort call stacks by the estimated value to the user
			sort.Slice(cs, func(i, j int) bool {
				return stackLess(cs[i], cs[j])
			})

			mu.Lock()
			vulnLookup[vulnerability] = cs
			mu.Unlock()
			wg.Done()
		}(current)
	}
	wg.Wait()
	return vulnLookup
}

// searchUnvisitedCallSites is based on code from the vuln package, which is released under BSD-style license: https://github.com/golang/vuln/blob/cac67f5c7c815b458cf683c41541d157d8217beb/vulncheck/witness.go#L172-L211
// resolveCallstacks fetches all callstacks based on the provided entrypoint
func resolveCallstacks(entryID int, result *vulncheck.Result) []vulncheck.CallStack {
	visitedSites := make(map[int]bool)

	vulEntryPoints := make(map[int]bool)
	for _, current := range result.Calls.Entries {
		vulEntryPoints[current] = true
	}

	var stacks []vulncheck.CallStack

	queue := list.New()
	queue.PushBack(types.NewCallChainLeave(result.Calls.Functions[entryID], nil, nil))

	for queue.Len() > 0 {
		ref := queue.Front()
		current := ref.Value.(*types.CallChain)
		queue.Remove(ref)

		if visitedSites[current.Fn.ID] {
			continue
		}
		visitedSites[current.Fn.ID] = true

		for _, cs := range searchUnvisitedCallSites(current.Fn.CallSites, visitedSites, result) {
			caller := result.Calls.Functions[cs.Parent]
			chain := types.NewCallChainLeave(caller, cs, current)

			if vulEntryPoints[caller.ID] {
				stacks = append(stacks, chain.CreateCallStack())
			}

			queue.PushBack(chain)
		}
	}

	return stacks
}

// searchUnvisitedCallSites is based on code from the vuln package, which is released under BSD-style license: https://github.com/golang/vuln/blob/cac67f5c7c815b458cf683c41541d157d8217beb/vulncheck/witness.go#L217-L239
// searchUnvisitedCallSites will go through the provided input and checkout the parent, while ensuring previously visited sites are not visited again
// It finally returns a list of all new callsites based on input
func searchUnvisitedCallSites(input []*vulncheck.CallSite, visitedSites map[int]bool, result *vulncheck.Result) []*vulncheck.CallSite {
	callSites := make(map[int]*vulncheck.CallSite)
	for _, cs := range input {
		if visitedSites[cs.Parent] {
			continue
		}

		callSites[cs.Parent] = cs
	}

	var functions []*vulncheck.FuncNode
	for id := range callSites {
		functions = append(functions, result.Calls.Functions[id])
	}

	var unvisitedSites []*vulncheck.CallSite
	for _, fn := range functions {
		unvisitedSites = append(unvisitedSites, callSites[fn.ID])
	}

	return unvisitedSites
}

// confidence was taken directly from the vuln package, which is released under BSD-style license: https://github.com/golang/vuln/blob/cac67f5c7c815b458cf683c41541d157d8217beb/vulncheck/witness.go#L302-L320
// stackLess compares two call stacks in terms of their estimated
// value to the user. Shorter stacks generally come earlier in the ordering.
//
// Two stacks are lexicographically ordered by:
// 1) their estimated level of confidence in being a real call stack,
// 2) their length, and 3) the number of dynamic call sites in the stack.
func stackLess(left vulncheck.CallStack, right vulncheck.CallStack) bool {
	if c1, c2 := confidence(left), confidence(right); c1 != c2 {
		return c1 < c2
	}

	if len(left) != len(right) {
		return len(left) < len(right)
	}

	if w1, w2 := weight(left), weight(right); w1 != w2 {
		return w1 < w2
	}

	return true
}

// confidence was taken directly from the vuln package, which is released under BSD-style license: https://github.com/golang/vuln/blob/cac67f5c7c815b458cf683c41541d157d8217beb/vulncheck/witness.go#L286-L294
// confidence computes an approximate measure of whether the stack
// is realizable in practice. Currently, it equals the number of call
// sites in stack that go through standard libraries. Such call stacks
// have been experimentally shown to often result in false positives.
func confidence(stack vulncheck.CallStack) int {
	c := 0
	for _, e := range stack {
		if isStdPackage(e.Function.PkgPath) {
			c += 1
		}
	}
	return c
}

// weight was taken directly from the vuln package, which is released under BSD-style license: https://github.com/golang/vuln/blob/cac67f5c7c815b458cf683c41541d157d8217beb/vulncheck/witness.go#L270-L280
// isStdPackage checks if the provided pkg is a standard package
func isStdPackage(pkg string) bool {
	if pkg == "" {
		return false
	}
	// std packages do not have a "." in their path. For instance, see
	// Contains in pkgsite/+/refs/heads/master/internal/stdlbib/stdlib.go.
	if i := strings.IndexByte(pkg, '/'); i != -1 {
		pkg = pkg[:i]
	}
	return !strings.Contains(pkg, ".")
}

// weight was taken directly from the vuln package, which is released under BSD-style license: https://github.com/golang/vuln/blob/cac67f5c7c815b458cf683c41541d157d8217beb/vulncheck/witness.go#L260-L268
// weight computes an approximate measure of how easy is to understand the call
// stack when presented to the client as a witness. The smaller the value, the more
// understandable the stack is. Currently defined as the number of unresolved
// call sites in the stack.
func weight(stack vulncheck.CallStack) int {
	//
	w := 0
	for _, e := range stack {
		if e.Call != nil && !e.Call.Resolved {
			w += 1
		}
	}
	return w
}
