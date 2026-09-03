package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
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
		meta := fmt.Sprintf("     frame: 0x%X", f.FrameSize)
		meta += fmt.Sprintf("   callers: %d", f.Callers)
		p("%s", meta)
		apis := distinctAPIs(f)
		if len(apis) > 0 {
			p("     apis : %s", strings.Join(apis, ", "))
		}
		if len(f.Strings) > 0 {
			p("     strs : %s", strings.Join(quoteAll(f.Strings, 6), ", "))
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

// TriageMarkdown writes the ranked functions as Markdown: a summary table plus
// per-function detail for each scored function (up to top; 0 = all).
func TriageMarkdown(w io.Writer, funcs []analysis.Func, top int) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }

	scored := 0
	for _, f := range funcs {
		if f.Score > 0 {
			scored++
		}
	}
	p("# Triage\n")
	p("%d functions analyzed, %d with exploitability signal. Ranked most-interesting first.\n", len(funcs), scored)

	p("| # | Score | Function | Address | Frame | Callers | APIs |")
	p("| --- | --- | --- | --- | --- | --- | --- |")
	shown := 0
	for _, f := range funcs {
		if f.Score <= 0 {
			continue
		}
		if top > 0 && shown >= top {
			break
		}
		shown++
		apis := strings.Join(distinctAPIs(f), ", ")
		if len(apis) > 80 {
			apis = apis[:77] + "..."
		}
		p("| %d | %d | `%s` | `0x%08X` | `0x%X` | %d | %s |",
			shown, f.Score, f.Name, f.Start, f.FrameSize, f.Callers, apis)
	}

	p("\n## Details\n")
	shown = 0
	for _, f := range funcs {
		if f.Score <= 0 {
			continue
		}
		if top > 0 && shown >= top {
			break
		}
		shown++
		p("### %s  (score %d)\n", f.Name, f.Score)
		p("- Address: `0x%08X`  |  WinDbg: `uf 0x%08X`", f.Start, f.Start)
		p("- Frame: `0x%X`  |  Callers: %d", f.FrameSize, f.Callers)
		if apis := distinctAPIs(f); len(apis) > 0 {
			p("- APIs: %s", strings.Join(apis, ", "))
		}
		if len(f.Strings) > 0 {
			p("- Strings: %s", strings.Join(quoteAll(f.Strings, 8), ", "))
		}
		for _, r := range f.Reasons {
			p("  - %s", r)
		}
		p("")
	}
}

// quoteAll quotes up to max strings for display, truncating long ones.
func quoteAll(ss []string, max int) []string {
	var out []string
	for i, s := range ss {
		if i >= max {
			out = append(out, fmt.Sprintf("(+%d more)", len(ss)-max))
			break
		}
		if len(s) > 40 {
			s = s[:37] + "..."
		}
		out = append(out, strconv.Quote(s))
	}
	return out
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
