package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"osed/recon/internal/badchars"
)

// alwaysTest are the bytes to verify on every target regardless of prediction.
var alwaysTest = []byte{0x00, 0x0a, 0x0d}

// BadcharsJSON writes the prediction as JSON.
func BadcharsJSON(w io.Writer, cands []badchars.Candidate, scoped int) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Scoped     int                  `json:"functions_in_scope"`
		Candidates []badchars.Candidate `json:"candidates"`
	}{scoped, cands})
}

// BadcharsText writes a human-readable prediction.
func BadcharsText(w io.Writer, cands []badchars.Candidate, scoped int) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	line := strings.Repeat("=", 60)

	p("%s", line)
	p("CANDIDATE BAD CHARS - static prediction from %d input-path function(s)", scoped)
	p("VERIFY dynamically: send \\x01..\\xff and compare the buffer in WinDbg.")
	p("%s", line)

	if scoped == 0 {
		p("\nNo input-handling functions identified (no recv/ReadFile/fread reached).")
		p("Re-run with --all to scan every function, or use the cdb path on a crash.")
		return
	}

	byConf := map[string][]badchars.Candidate{}
	for _, c := range cands {
		byConf[c.Confidence] = append(byConf[c.Confidence], c)
	}
	labels := []struct{ key, title string }{
		{"high", "High confidence (null terminator)"},
		{"likely", "Likely (control/whitespace delimiter checks)"},
		{"possible", "Possible (punctuation compared in the input path)"},
		{"keyword", "Protocol/keyword bytes (compared, but probably NOT bad chars)"},
	}
	for _, l := range labels {
		cs := byConf[l.key]
		if len(cs) == 0 {
			continue
		}
		p("\n%s:", l.title)
		for _, c := range cs {
			p("  0x%02X %-4s x%-2d  %s", c.Byte, printable(c.Byte), c.Sites, firstReason(c.Reasons))
		}
	}

	p("\n%s", line)
	p("Suggested set to test first: %s", hexList(suggested(cands)))
	p("Always test regardless: 00 0a 0d")
}

// BadcharsMarkdown writes the prediction as Markdown.
func BadcharsMarkdown(w io.Writer, cands []badchars.Candidate, scoped int) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p("# Candidate bad chars (static prediction)\n")
	p("From %d input-path function(s). **Verify dynamically** by sending "+
		"`\\x01..\\xff` and comparing the buffer in WinDbg.\n", scoped)
	if scoped == 0 {
		p("_No input-handling functions identified. Try `--all`, or the cdb path on a crash._")
		return
	}
	p("| Byte | ASCII | Confidence | Sites | Evidence |")
	p("| --- | --- | --- | --- | --- |")
	for _, c := range cands {
		p("| `0x%02X` | %s | %s | %d | %s |", c.Byte, printable(c.Byte), c.Confidence, c.Sites, firstReason(c.Reasons))
	}
	p("\n**Suggested set to test first:** `%s`  ", hexList(suggested(cands)))
	p("**Always test regardless:** `00 0a 0d`")
}

// suggested returns the high+likely bytes plus the universal 00/0a/0d.
func suggested(cands []badchars.Candidate) []byte {
	seen := map[byte]bool{}
	var out []byte
	for _, b := range alwaysTest {
		if !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	for _, c := range cands {
		if c.Confidence == "high" || c.Confidence == "likely" {
			if !seen[c.Byte] {
				seen[c.Byte] = true
				out = append(out, c.Byte)
			}
		}
	}
	return out
}

func hexList(bs []byte) string {
	var parts []string
	for _, b := range bs {
		parts = append(parts, fmt.Sprintf("%02x", b))
	}
	return strings.Join(parts, " ")
}

func printable(b byte) string {
	if b >= 0x20 && b < 0x7F {
		return "'" + string(rune(b)) + "'"
	}
	return "   "
}

func firstReason(rs []string) string {
	if len(rs) == 0 {
		return ""
	}
	extra := ""
	if len(rs) > 1 {
		extra = fmt.Sprintf(" (+%d more)", len(rs)-1)
	}
	return rs[0] + extra
}
