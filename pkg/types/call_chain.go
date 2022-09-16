package types

import (
	"fmt"

	"github.com/rs/zerolog"
	"golang.org/x/vuln/vulncheck"
)

type CallChain struct {
	Fn     *vulncheck.FuncNode
	Called *vulncheck.CallSite
	Child  *CallChain
}

func NewCallChainLeave(fn *vulncheck.FuncNode, call *vulncheck.CallSite, child *CallChain) *CallChain {
	return &CallChain{
		Fn:     fn,
		Called: call,
		Child:  child,
	}
}

func (c *CallChain) CreateCallStack() vulncheck.CallStack {
	if c == nil {
		return make(vulncheck.CallStack, 0)
	}

	return append(vulncheck.CallStack{vulncheck.StackEntry{Function: c.Fn, Call: c.Called}}, c.Child.CreateCallStack()...)
}

func PrintStack(log zerolog.Logger, stack vulncheck.CallStack) {
	for i, current := range stack {
		if current.Call == nil {
			log.Info().Msgf("[%d] %s.%s", i, current.Function.PkgPath, current.Function.Name)
		} else {
			log.Info().Msgf("[%d] %s %s => %s", i, current.Function.PkgPath, current.Function.Name, current.Call.Name)
		}

	}
}

func Stack(stack vulncheck.CallStack) string {
	output := ""

	for i, current := range stack {
		if current.Call == nil {
			output += fmt.Sprintf("[%d] Vulnerability %s.%s\n", i, current.Function.PkgPath, current.Function.Name)
		} else {
			output += fmt.Sprintf("[%d] %s %s => %s\n", i, current.Function.PkgPath, current.Function.Name, current.Call.Name)
		}

	}

	return output
}
