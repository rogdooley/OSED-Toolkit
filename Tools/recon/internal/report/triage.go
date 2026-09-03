package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"osed/recon/internal/analysis"
)

// TriageJSON writes the ranked functions as indented JSON.
func TriageJSON(w io.Writer, funcs []analysis.Func) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(funcs)
}

// TriageText writes a ranked, human-readable triage report. Only functions
// with a non-zero score are shown by default; top is the maximum to print
// (0 = all scored functions).
func TriageText(w io.Writer, funcs []analysis.Func, top int) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	line := strings.Repeat("=", 60)

	scored := 0
	for _, f := range funcs {
		if f.Score > 0 {
			scored++
		}
	}
	p("%s", line)
	p("TRIAGE - %d functions analyzed, %d with exploitability signal", len(funcs), scored)
	p("ranked most-interesting first; start at the top and read those functions in WinDbg")
	p("%s", line)

	shown := 0
	for _, f := range funcs {
		if f.Score <= 0 {
			continue
		}
		if top > 0 && shown >= top {
			p("\n... (%d more scored functions; pass --top 0 for all)", scored-shown)
			break
		}
		shown++
		p("\n[%d] %s  @ 0x%08X   uf 0x%08X", f.Score, f.Name, f.Start, f.Start)
		if f.FrameSize > 0 {
			p("     frame: 0x%X bytes", f.FrameSize)
		}
		apis := distinctAPIs(f)
		if len(apis) > 0 {
			p("     apis : %s", strings.Join(apis, ", "))
		}
		for _, r := range f.Reasons {
			p("      - %s", r)
		}
	}
	if scored == 0 {
		p("\nNo functions scored. The binary may be stripped of symbols and use")
		p("indirect calls throughout; try the cdb frontend with a symbol-resolved dump.")
	}
}

func distinctAPIs(f analysis.Func) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range f.Calls {
		if c.API != "" && !seen[c.API] {
			seen[c.API] = true
			out = append(out, c.API)
		}
	}
	return out
}
