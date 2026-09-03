package cdb

import (
	"strings"
	"testing"

	"osed/recon/internal/analysis"
)

// A realistic-looking `uf` dump for two functions: a vulnerable handler that
// reads from the socket and copies into a stack buffer, and a benign helper.
const dump = `vuln!handle_request:
00401000 55              push    ebp
00401001 8bec            mov     ebp,esp
00401003 81ec00040000    sub     esp,400h
00401009 8b4508          mov     eax,dword ptr [ebp+8]
0040100c 50              push    eax
0040100d ff1508204000    call    dword ptr [WS2_32!recv (00402008)]
00401013 8d85fcfbffff    lea     eax,[ebp-404h]
00401019 50              push    eax
0040101a e8e1010000      call    vuln!strcpy (00401200)
0040101f c9              leave
00401020 c3              ret

vuln!log_line:
00401300 55              push    ebp
00401301 e8fafeffff      call    msvcrt!printf (00401400)
00401306 c3              ret
`

func TestParseRanksVulnerableHandler(t *testing.T) {
	funcs := Parse(strings.NewReader(dump))
	if len(funcs) != 2 {
		t.Fatalf("got %d funcs, want 2", len(funcs))
	}

	handler := findFunc(funcs, "handle_request")
	if handler == nil {
		t.Fatal("handle_request not parsed")
	}
	if handler.FrameSize != 0x400 {
		t.Fatalf("frame = 0x%X, want 0x400", handler.FrameSize)
	}
	apis := apiSet(handler.Calls)
	if !apis["recv"] || !apis["strcpy"] {
		t.Fatalf("expected recv and strcpy resolved, got %v", apis)
	}

	// End to end: the handler must outrank the benign logger after ranking.
	ranked := analysis.Rank(funcs)
	if len(ranked) == 0 || ranked[0].Name != "handle_request" {
		t.Fatalf("top ranked = %v, want handle_request", topName(ranked))
	}
}

func findFunc(fs []analysis.Func, name string) *analysis.Func {
	for i := range fs {
		if fs[i].Name == name {
			return &fs[i]
		}
	}
	return nil
}

func apiSet(calls []analysis.Call) map[string]bool {
	m := map[string]bool{}
	for _, c := range calls {
		if c.API != "" {
			m[c.API] = true
		}
	}
	return m
}

func topName(fs []analysis.Func) string {
	if len(fs) == 0 {
		return "(none)"
	}
	return fs[0].Name
}
