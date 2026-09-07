package pseudo

import (
	"strconv"
	"strings"
)

// sanitizeASCII drops non-ASCII bytes (IDA xref arrows are UTF-8) and trims,
// so the emitter only ever deals with plain ASCII.
func sanitizeASCII(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}

// stripComment removes a trailing `; ...` comment from a line.
func stripComment(s string) string {
	if i := strings.IndexByte(s, ';'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// isSeparator reports whether a comment body is an IDA section divider or a
// subroutine banner, both of which mark a function boundary.
func isSeparator(body string) bool {
	if body == "" {
		return false
	}
	if strings.Contains(body, "S U B R O U T I N E") {
		return true
	}
	only := strings.Trim(body, "-=")
	return only == ""
}

func isPrefix(m string) bool {
	switch m {
	case "rep", "repe", "repz", "repne", "repnz", "lock":
		return true
	}
	return false
}

// looksLikeMnemonic rejects stray tokens (data directives, `db`, symbol names)
// that are not instructions we want to transliterate.
func looksLikeMnemonic(m string) bool {
	if m == "" {
		return false
	}
	// A rep-folded mnemonic like "rep movsd" is fine.
	if i := strings.IndexByte(m, ' '); i >= 0 {
		m = m[i+1:]
	}
	for _, c := range m {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	switch m {
	case "db", "dd", "dw", "dq", "align", "public", "assume", "end", "dt", "unicode":
		return false
	}
	return true
}

func sizeOf(kind string) int {
	switch kind {
	case "byte":
		return 1
	case "word":
		return 2
	case "dword":
		return 4
	case "qword":
		return 8
	case "tbyte":
		return 10
	case "xmmword":
		return 16
	}
	return 0
}

// splitTopComma splits an operand string on commas that are not nested inside
// brackets (x86 memory operands never contain a top-level comma, but this keeps
// scaled-index forms safe).
func splitTopComma(s string) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[', '(':
			depth++
		case ']', ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

func parseHexU(s string) uint64 {
	v, _ := strconv.ParseUint(strings.TrimSpace(s), 16, 64)
	return v
}

// parseSignedImm parses an IDA immediate that may be decimal or trailing-h hex
// and may be negative: "8", "-18h", "0Ch", "-4".
func parseSignedImm(s string) int64 {
	s = strings.TrimSpace(s)
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}
	base := 10
	if strings.HasSuffix(s, "h") {
		s = strings.TrimSuffix(s, "h")
		base = 16
	} else if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
		base = 16
	}
	v, err := strconv.ParseInt(s, base, 64)
	if err != nil {
		return 0
	}
	if neg {
		v = -v
	}
	return v
}

func hexLower(v uint64) string {
	return strconv.FormatUint(v, 16)
}
