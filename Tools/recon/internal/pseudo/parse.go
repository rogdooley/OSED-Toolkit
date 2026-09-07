// Package pseudo turns an IDA Pro disassembly listing (pasted as text) into
// readable C-like pseudocode. It exists to fill the one gap in the OSED exam
// toolchain: IDA's disassembler is available but the Hex-Rays decompiler is
// not, so there is no local way to get pseudocode for a function.
//
// The transform is deliberately a faithful transliteration, not a decompiler.
// It does NOT recover types or structure control flow into if/while; it keeps
// register names (so the output lines up with what you see in WinDbg) and
// renders branches as `if (cond) goto label;`. What it does reconstruct is the
// noisy, mechanical stuff that eats reading time: call arguments and calling
// convention, compare-then-branch conditions, pretty operands, and the
// prologue/epilogue/guard boilerplate that can be dropped.
//
// Two input shapes are accepted: the linear listing with `.text:ADDR` line
// prefixes, and IDA graph-view text with no addresses. UTF-8 in comments
// (IDA's xref arrows) is tolerated and discarded; all output is plain ASCII.
package pseudo

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

// Var is one entry from an IDA stack-frame table, e.g. `var_18= dword ptr -18h`
// or `arg_0= dword ptr 8`.
type Var struct {
	Name  string // as IDA named it: var_18, arg_0, s, buf
	Off   int64  // signed ebp offset (negative = local, positive = argument)
	Size  int    // 1, 2, 4, 8 from byte/word/dword/qword; 0 if unknown
	Bytes int64  // span to the next-higher slot, used to spot arrays/buffers
	IsArg bool
}

// Inst is one decoded instruction line.
type Inst struct {
	Addr    uint64 // absolute address, if the listing carried one
	HasAddr bool
	Labels  []string // labels that appear immediately before this instruction
	Mnem    string   // lowercased mnemonic
	Ops     []string // operands, split on top-level commas, whitespace-trimmed
	Comment string   // trailing `; ...` comment, ASCII-sanitized
}

// Func is one parsed function (or a synthesized chunk of loose code).
type Func struct {
	Name     string
	Proto    string // raw prototype comment line, if IDA emitted one
	RetType  string // return type parsed from the prototype (e.g. "DWORD")
	CallConv string // calling convention parsed from the prototype
	Vars     []Var
	Insts    []Inst
	HasProc  bool // saw an explicit `proc`/`endp` bracket
}

// arg returns the argument variables (positive offsets), lowest offset first.
func (f *Func) varByName(name string) (Var, bool) {
	for _, v := range f.Vars {
		if v.Name == name {
			return v, true
		}
	}
	return Var{}, false
}

var (
	// `.text:14801000`, `UPX0:00401000`, etc. followed by the real content.
	reAddrPrefix = regexp.MustCompile(`^\s*[A-Za-z_.][\w.]*:([0-9A-Fa-f]+)\b[ \t]?(.*)$`)
	// `var_18= dword ptr -18h`  /  `s= dword ptr  8`
	reFrameVar = regexp.MustCompile(`^([A-Za-z_$@?][\w$@?]*)\s*=\s*(byte|word|dword|qword|tbyte|xmmword)\s+ptr\s+([+-]?[0-9A-Fa-f]+h?)\s*$`)
	// a bare label line: `loc_1480101A:`
	reLabel = regexp.MustCompile(`^([A-Za-z_$@?][\w$@?]*):$`)
	// prototype comment: `; DWORD __stdcall sub_14801040(LPVOID lpThreadParameter)`
	reProto = regexp.MustCompile(`(__cdecl|__stdcall|__fastcall|__thiscall|__usercall|__userpurge)`)
)

// Parse reads an IDA listing and returns the functions it found. The parser is
// forgiving: any line it does not understand is skipped rather than aborting.
func Parse(r io.Reader) []Func {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var funcs []Func
	var cur *Func
	var pendingLabels []string
	var pendingProto string

	newFunc := func(name string, hasProc bool) {
		cur = &Func{Name: name, HasProc: hasProc}
		if pendingProto != "" {
			applyProto(cur, pendingProto)
			pendingProto = ""
		}
	}
	flush := func() {
		if cur != nil && (len(cur.Insts) > 0 || cur.HasProc) {
			funcs = append(funcs, *cur)
		}
		cur = nil
		pendingLabels = nil
	}

	for sc.Scan() {
		raw := sc.Text()
		addr, hasAddr, rest := stripAddrPrefix(raw)
		trimmed := strings.TrimSpace(rest)
		if trimmed == "" {
			continue
		}

		// Comments: separators, attributes, xrefs, and the prototype line.
		if strings.HasPrefix(trimmed, ";") {
			body := strings.TrimSpace(strings.TrimLeft(trimmed, "; "))
			if isSeparator(body) {
				flush() // a new subroutine/chunk boundary
			}
			if reProto.MatchString(body) && strings.Contains(body, "(") {
				pendingProto = body
			}
			continue
		}

		fields := strings.Fields(trimmed)

		// `name proc near` / `name endp`
		if len(fields) >= 2 && fields[1] == "proc" {
			flush()
			newFunc(fields[0], true)
			continue
		}
		if len(fields) >= 2 && fields[1] == "endp" {
			flush()
			continue
		}

		// Frame-table entry.
		if m := reFrameVar.FindStringSubmatch(trimmed); m != nil {
			if cur == nil {
				newFunc("sub_"+hexLower(addr), false)
			}
			cur.Vars = append(cur.Vars, parseFrameVar(m))
			continue
		}

		// Label line.
		labelText := stripComment(trimmed)
		if m := reLabel.FindStringSubmatch(strings.TrimSpace(labelText)); m != nil {
			pendingLabels = append(pendingLabels, m[1])
			continue
		}

		// Otherwise: an instruction.
		mnem, ops, comment, ok := parseInst(trimmed)
		if !ok {
			continue
		}
		if cur == nil {
			name := "sub_" + hexLower(addr)
			if !hasAddr {
				name = "func"
			}
			newFunc(name, false)
		}
		cur.Insts = append(cur.Insts, Inst{
			Addr:    addr,
			HasAddr: hasAddr,
			Labels:  pendingLabels,
			Mnem:    mnem,
			Ops:     ops,
			Comment: comment,
		})
		pendingLabels = nil
	}
	flush()

	finalizeVars(funcs)
	return funcs
}

// stripAddrPrefix removes an IDA `segment:address` prefix if present and returns
// the address plus the remaining content of the line.
func stripAddrPrefix(line string) (addr uint64, has bool, rest string) {
	if m := reAddrPrefix.FindStringSubmatch(line); m != nil {
		return parseHexU(m[1]), true, m[2]
	}
	return 0, false, line
}

// parseInst splits `mnemonic  operands  ; comment` into its parts. Segment and
// size decoration inside operands is left for the emitter to render.
func parseInst(s string) (mnem string, ops []string, comment string, ok bool) {
	body := s
	if i := strings.IndexByte(body, ';'); i >= 0 {
		comment = sanitizeASCII(strings.TrimSpace(body[i+1:]))
		body = strings.TrimSpace(body[:i])
	}
	if body == "" {
		return "", nil, "", false
	}
	fields := strings.Fields(body)
	mnem = strings.ToLower(fields[0])
	// Fold a rep/lock prefix into the following mnemonic name.
	if isPrefix(mnem) && len(fields) > 1 {
		mnem = mnem + " " + strings.ToLower(fields[1])
		fields = append(fields[:1], fields[2:]...)
	}
	if !looksLikeMnemonic(mnem) {
		return "", nil, "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(body, fields[0]))
	if rest != "" {
		for _, p := range splitTopComma(rest) {
			ops = append(ops, strings.TrimSpace(p))
		}
	}
	return mnem, ops, comment, true
}

func parseFrameVar(m []string) Var {
	v := Var{Name: m[1], Size: sizeOf(m[2])}
	v.Off = parseSignedImm(m[3])
	v.IsArg = v.Off > 0
	return v
}

// finalizeVars computes each local's byte span (distance to the next slot),
// which the emitter uses to flag stack buffers.
func finalizeVars(funcs []Func) {
	for fi := range funcs {
		vs := funcs[fi].Vars
		// Locals: negative offsets, closer to zero = higher in memory.
		for i := range vs {
			if vs[i].IsArg {
				continue
			}
			best := int64(0)
			found := false
			for j := range vs {
				if vs[j].IsArg {
					continue // span is measured between locals only
				}
				if vs[j].Off > vs[i].Off && (!found || vs[j].Off < best) {
					best = vs[j].Off
					found = true
				}
			}
			if found {
				vs[i].Bytes = best - vs[i].Off
			}
		}
	}
}

func applyProto(f *Func, proto string) {
	f.Proto = proto
	m := reProto.FindString(proto)
	f.CallConv = m
	// Return type is the first token before the convention keyword.
	if m != "" {
		if idx := strings.Index(proto, m); idx > 0 {
			f.RetType = strings.TrimSpace(proto[:idx])
		}
	}
}
