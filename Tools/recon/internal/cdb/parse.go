// Package cdb turns a headless WinDbg/cdb text dump into the shared
// analysis.Func model, so the ranking that the disasm frontend applies to a
// static image can also be applied to debugger output. This is the "split"
// workflow: generate the dump on the locked-down exam box, rank it anywhere.
//
// Expected input is `uf` (unassemble-function) output, optionally many
// functions concatenated. A recommended generator command is documented in
// the recon README. The parser is deliberately forgiving: unrecognized lines
// are ignored rather than aborting the run.
package cdb

import (
	"bufio"
	"io"
	"strconv"
	"strings"

	"osed/recon/internal/analysis"
	"osed/recon/internal/apis"
)

// Parse reads a cdb text dump and returns the discovered functions (unranked).
func Parse(r io.Reader) []analysis.Func {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var funcs []analysis.Func
	var cur *analysis.Func
	flush := func() {
		if cur != nil {
			funcs = append(funcs, *cur)
			cur = nil
		}
	}

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if name, ok := functionHeader(trimmed); ok {
			flush()
			cur = &analysis.Func{Name: name, Start: leadingHexOf(line)}
			continue
		}
		if cur == nil {
			// Some dumps open straight into instructions; synthesize a func.
			cur = &analysis.Func{Name: "func"}
		}

		addr, mnem, ops, ok := instruction(line)
		if !ok {
			continue
		}
		if cur.Start == 0 && addr != 0 {
			cur.Start = addr
		}
		classify(cur, addr, mnem, ops)
	}
	flush()
	return funcs
}

// functionHeader matches a symbol line that opens a function, e.g.
// "module!Handler:" but not a mid-function block label "module!Handler+0x1a:".
func functionHeader(s string) (string, bool) {
	if !strings.HasSuffix(s, ":") {
		return "", false
	}
	body := strings.TrimSuffix(s, ":")
	if body == "" || strings.Contains(body, "+0x") || strings.Contains(body, " ") {
		return "", false
	}
	// A pure hex token followed by ':' is not a symbol header.
	if _, err := strconv.ParseUint(body, 16, 64); err == nil {
		return "", false
	}
	if i := strings.LastIndex(body, "!"); i >= 0 {
		body = body[i+1:]
	}
	return body, true
}

// instruction parses "<addr> <bytes> <mnemonic> <operands>" and returns the
// address, mnemonic (lowercased, rep-prefix folded in) and operand string.
func instruction(line string) (addr uint64, mnem, ops string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return 0, "", "", false
	}
	a, err := strconv.ParseUint(fields[0], 16, 64)
	if err != nil {
		return 0, "", "", false
	}
	if !isHex(fields[1]) { // second token must be the opcode bytes
		return 0, "", "", false
	}
	rest := fields[2:]
	m := strings.ToLower(rest[0])
	if (m == "rep" || m == "repne" || m == "repnz" || m == "repe" || m == "repz" || m == "lock") && len(rest) > 1 {
		m = strings.ToLower(rest[1])
		rest = rest[1:]
	}
	ops = strings.Join(rest[1:], " ")
	return a, m, ops, true
}

func classify(fn *analysis.Func, addr uint64, mnem, ops string) {
	switch {
	case mnem == "call":
		api := apiFromOperand(ops)
		fn.Calls = append(fn.Calls, analysis.Call{Site: addr, API: api})
	case mnem == "sub" && strings.HasPrefix(strings.ToLower(ops), "esp,"),
		mnem == "sub" && strings.HasPrefix(strings.ToLower(ops), "rsp,"):
		if v, ok := parseImm(ops[strings.Index(ops, ",")+1:]); ok && v > fn.FrameSize {
			fn.FrameSize = v
		}
	case strings.HasPrefix(mnem, "movs") || strings.HasPrefix(mnem, "stos"):
		fn.StringOps = true
	}
}

// apiFromOperand extracts an API name from a call operand and returns it if it
// matches a known API table, else "". Handles "mod!name (addr)",
// "dword ptr [mod!_imp__name (addr)]" and bare "name".
func apiFromOperand(ops string) string {
	s := ops
	if i := strings.LastIndex(s, "!"); i >= 0 {
		s = s[i+1:]
	}
	// cut at first space, paren or bracket
	s = strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '(' || r == ')' || r == '[' || r == ']'
	})[0]
	s = normalizeSymbol(s)
	if apis.Category(s) != "" {
		return s
	}
	return ""
}

// normalizeSymbol strips import-thunk and stdcall decoration:
// _imp__lstrcpyA -> lstrcpyA, _recv -> recv, name@8 -> name.
func normalizeSymbol(s string) string {
	for _, p := range []string{"_imp__", "_imp_", "__imp_"} {
		s = strings.TrimPrefix(s, p)
	}
	s = strings.TrimLeft(s, "_")
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	return s
}

// parseImm parses a WinDbg immediate like "400h", "0x400" or "1024".
func parseImm(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, "h")
	s = strings.TrimPrefix(s, "0x")
	v, err := strconv.ParseInt(s, 16, 64)
	if err != nil {
		return 0, false
	}
	if v < 0 {
		v = -v
	}
	return v, true
}

func leadingHexOf(line string) uint64 {
	f := strings.Fields(line)
	if len(f) == 0 {
		return 0
	}
	v, err := strconv.ParseUint(f[0], 16, 64)
	if err != nil {
		return 0
	}
	return v
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
