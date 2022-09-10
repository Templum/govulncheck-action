package vulncheck

type ScanResult struct {
	Calls    CallGraph   // TODO: Implement
	Imports  interface{} // TODO: Implement
	Requires interface{} // TODO: Implement
	Vulns    interface{} // TODO: Implement
}

type CallGraph struct {
	Functions map[int]FnNode
	Entries   []int
}

type FnNode struct {
	ID        int
	Name      string
	RecvType  string
	PkgPath   string
	Pos       Position
	Callsites []interface{} // Probably not needed
}

type Position struct {
	Filename string
	Offset   int // starts at 0
	Line     int // Starts at 1
	Column   int // starts at 1
}

type Vulnerability struct {
	OSV Entry

	Symbol      string
	PkgPath     string
	ModPath     string
	CallSink    int // If unavailable == 0
	ImportSink  int // If unavailable == 0
	RequireSink int // If unavailable == 0
}
