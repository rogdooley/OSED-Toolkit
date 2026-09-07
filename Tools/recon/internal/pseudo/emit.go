package pseudo

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

const ptrSize = 4 // x86

// Emit writes C-like pseudocode for one function to w.
func Emit(w io.Writer, f Func) {
	e := &emitter{f: &f, pending: map[string]string{}}
	e.header()

	insts := f.Insts
	insts = insts[e.skipPrologue(insts, 0):]
	e.c = buildCFG(insts)
	e.renderRange(0, len(e.c.blocks), 4)

	e.emit(0, "}")
	for _, ln := range e.out {
		fmt.Fprintln(w, ln)
	}
}

type emitter struct {
	f       *Func
	c       *cfg
	out     []string
	indent  int               // current statement indent
	pending map[string]string // r32 -> deferred value from a mov/lea, not yet emitted
	order   []string          // pending keys in insertion order, for stable flushing
	pushes  []arg             // pending stack arguments
	lastCmp *cmpState
}

type arg struct {
	expr    string
	comment string
}

type cmpState struct{ kind, a, b string }

func (e *emitter) emit(indent int, format string, a ...any) {
	if indent < 0 {
		indent = 0
	}
	e.out = append(e.out, strings.Repeat(" ", indent)+fmt.Sprintf(format, a...))
}

// ---- structured rendering ----------------------------------------------------

// renderRange emits blocks [lo, hi) at the given indent, recognizing single
// block do/while loops and simple if-then regions and otherwise falling back to
// a labeled block ending in an honest goto.
func (e *emitter) renderRange(lo, hi, ind int) {
	i := lo
	for i < hi {
		b := e.c.blocks[i]
		if e.c.selfLoop(i) {
			e.emit(ind, "do {")
			e.renderStmts(b, ind+4) // head label and back-edge suppressed
			e.emit(ind, "} while (%s);", e.condition(b.CondInst.Mnem))
			i++
			continue
		}
		if join, ok := e.c.ifThenRange(i, hi); ok {
			e.labels(b, ind-2)
			e.renderStmts(b, ind) // guard body, condition captured
			e.emit(ind, "if (%s) {", e.negatedCondition(b.CondInst.Mnem))
			e.renderRange(i+1, join, ind+4)
			e.emit(ind, "}")
			i = join
			continue
		}
		e.renderBlock(b, ind)
		i++
	}
}

// renderBlock emits an unstructured block: its label, its statements, and its
// terminator as a goto / return / tail call.
func (e *emitter) renderBlock(b Block, ind int) {
	e.labels(b, ind-2)
	e.renderStmts(b, ind)
	switch b.Kind {
	case termRet:
		e.emit(ind, "return;")
	case termJmp:
		if b.Target == "" {
			e.emit(ind, "// jmp %s (indirect)", strings.Join(b.JmpInst.Ops, ", "))
		} else if strings.HasPrefix(b.Target, "sub_") && b.Idx == len(e.c.blocks)-1 {
			e.emit(ind, "return %s(); // tail call", b.Target)
		} else {
			e.emit(ind, "goto %s;", b.Target)
		}
	case termCond:
		e.emit(ind, "if (%s) goto %s;", e.condition(b.CondInst.Mnem), b.Target)
	}
}

func (e *emitter) labels(b Block, ind int) {
	for _, lb := range b.Labels {
		e.emit(ind, "%s:", lb)
	}
}

// renderStmts renders a block's body statements (never its terminator) at the
// given indent, then flushes any deferred register loads still live.
func (e *emitter) renderStmts(b Block, ind int) {
	e.indent = ind
	e.pushes = nil
	for i := 0; i < len(b.Body); {
		i += e.handleStmt(b.Body, i)
	}
	e.flushPending()
}

// ---- deferred register values ------------------------------------------------

func (e *emitter) setPending(reg, val string) {
	if _, ok := e.pending[reg]; !ok {
		e.order = append(e.order, reg)
	}
	e.pending[reg] = val
}

// valOf returns a register's deferred value (consuming it) or the register name.
func (e *emitter) valOf(reg string) string {
	if v, ok := e.pending[reg]; ok {
		e.dropPending(reg)
		return v
	}
	return reg
}

func (e *emitter) dropPending(reg string) {
	if _, ok := e.pending[reg]; !ok {
		return
	}
	delete(e.pending, reg)
	for i, k := range e.order {
		if k == reg {
			e.order = append(e.order[:i], e.order[i+1:]...)
			break
		}
	}
}

// flushPending emits deferred loads still live at a block boundary (a value
// loaded before a loop stays visible inside it).
func (e *emitter) flushPending() {
	for _, reg := range e.order {
		e.emit(e.indent, "%s = %s;", reg, e.pending[reg])
	}
	e.pending = map[string]string{}
	e.order = nil
}

// ---- header ------------------------------------------------------------------

func (e *emitter) header() {
	ret := e.f.RetType
	if ret == "" {
		ret = "int"
	}
	conv := e.f.CallConv
	if conv != "" {
		conv = " " + conv
	}
	var params, locals, buffers []string
	for _, v := range e.f.Vars {
		switch {
		case v.IsArg:
			params = append(params, "int "+v.Name)
		case v.Bytes >= 16:
			buffers = append(buffers, fmt.Sprintf("%s[0x%X]", v.Name, v.Bytes))
		default:
			locals = append(locals, v.Name)
		}
	}
	if e.f.Proto != "" {
		e.emit(0, "// from IDA: %s", e.f.Proto)
	}
	if len(buffers) > 0 {
		e.emit(0, "// stack buffers: %s", strings.Join(buffers, ", "))
	}
	if len(locals) > 0 {
		e.emit(0, "// locals: %s", strings.Join(locals, ", "))
	}
	e.emit(0, "%s%s %s(%s)", ret, conv, e.f.Name, strings.Join(params, ", "))
	e.emit(0, "{")
}

// ---- statements --------------------------------------------------------------

// handleStmt renders one body instruction and returns how many following
// instructions it also consumed (call cleanup, a folded result mov).
func (e *emitter) handleStmt(body []Inst, i int) int {
	in := body[i]
	switch {
	case in.Mnem == "push":
		e.pushes = append(e.pushes, arg{expr: e.read(in.Ops, 0), comment: in.Comment})
		return 1
	case in.Mnem == "call":
		return 1 + e.doCall(body, i)
	case in.Mnem == "cmp", in.Mnem == "test":
		a := e.read(in.Ops, 0)
		b := a
		// `test eax, eax` names one operand twice; render it once so a deferred
		// load is not consumed differently on each side.
		if len(in.Ops) > 1 && !strings.EqualFold(strings.TrimSpace(in.Ops[0]), strings.TrimSpace(in.Ops[1])) {
			b = e.read(in.Ops, 1)
		}
		e.lastCmp = &cmpState{kind: in.Mnem, a: a, b: b}
		return 1
	case in.Mnem == "pop", in.Mnem == "leave", in.Mnem == "nop":
		return 1 // register restore / frame teardown: drop
	case in.Mnem == "mov" || in.Mnem == "movzx" || in.Mnem == "movsx":
		e.doMov(in)
		return 1
	case in.Mnem == "lea":
		dst := lowOp(in.Ops, 0)
		src := e.leaSource(in.Ops)
		if isR32(dst) {
			e.setPending(dst, src)
		} else {
			e.emit(e.indent, "%s = %s;", e.dst(in.Ops, 0), src)
		}
		return 1
	case in.Mnem == "int" && lowOp(in.Ops, 0) == "3":
		e.emit(e.indent, "__debugbreak();")
		return 1
	default:
		e.doArith(in)
		return 1
	}
}

func (e *emitter) doMov(in Inst) {
	dst := lowOp(in.Ops, 0)
	if dst == "esp" {
		return // stack-pointer adjustment is frame mechanics, not data (e.g. mov esp, ebp)
	}
	// Infer the memory access width from the paired register (al -> byte, etc.)
	// when IDA left the operand without an explicit `byte ptr`/`word ptr`.
	hint := regSizeOf(dst)
	if h := regSizeOf(lowOp(in.Ops, 1)); h != 0 {
		hint = h
	}
	val := e.readSized(in.Ops, 1, hint)
	if isR32(dst) {
		e.setPending(dst, val) // defer; folds into the consuming use
		return
	}
	e.emit(e.indent, "%s = %s;", e.dstSized(in.Ops, 0, hint), val)
	e.dropPending(canonReg(dst)) // sub-register write invalidates the parent
}

// doArith renders the common ALU instructions; anything unrecognized is echoed
// verbatim as a comment so nothing is silently dropped.
func (e *emitter) doArith(in Inst) {
	dst := e.dst(in.Ops, 0) // rendered destination (register name or memory)
	old := dst
	if r := lowOp(in.Ops, 0); isReg(r) {
		old = e.valOf(r) // old value folds a pending load: mov eax,x / add eax,4
	}
	bin := func(op string) {
		if len(in.Ops) >= 2 && in.Ops[0] == in.Ops[1] && op == "^" {
			e.emit(e.indent, "%s = 0;", dst) // xor r, r
			return
		}
		e.emit(e.indent, "%s = %s %s %s;", dst, old, op, e.read(in.Ops, 1))
	}
	switch in.Mnem {
	case "add":
		bin("+")
	case "sub":
		bin("-")
	case "and":
		bin("&")
	case "or":
		bin("|")
	case "xor":
		bin("^")
	case "shl", "sal":
		bin("<<")
	case "shr", "sar":
		bin(">>")
	case "imul", "mul":
		if len(in.Ops) >= 2 {
			bin("*")
		} else {
			e.echo(in)
		}
	case "inc":
		e.emit(e.indent, "%s = %s + 1;", dst, old)
	case "dec":
		e.emit(e.indent, "%s = %s - 1;", dst, old)
	case "neg":
		e.emit(e.indent, "%s = -%s;", dst, old)
	case "not":
		e.emit(e.indent, "%s = ~%s;", dst, old)
	default:
		e.echo(in)
	}
}

func (e *emitter) echo(in Inst) {
	if len(in.Ops) == 0 {
		e.emit(e.indent, "// %s", in.Mnem)
		return
	}
	e.emit(e.indent, "// %s %s", in.Mnem, strings.Join(in.Ops, ", "))
}

// ---- calls -------------------------------------------------------------------

func (e *emitter) doCall(insts []Inst, i int) int {
	target := e.callee(insts[i].Ops)
	raw := ""
	if len(insts[i].Ops) > 0 {
		raw = insts[i].Ops[0]
	}
	switch classifyCallee(raw) {
	case noiseGuard:
		return 0
	case noiseSEHProlog:
		e.pushes = nil
		e.emit(e.indent, "// SEH prologue")
		return 0
	case noiseSEHEpilog:
		e.pushes = nil
		e.emit(e.indent, "// SEH epilogue")
		return 0
	}

	argc, cleanup := e.argCount(insts, i)
	args := e.takeArgs(argc)
	e.pushes = nil // leftover pushes were register saves
	e.dropCallerSaved()
	call := fmt.Sprintf("%s(%s)", target, strings.Join(args, ", "))

	// Fold the result into an immediately following `mov <dst>, eax`. Emit it in
	// place (never defer): a call has side effects and must not be reordered.
	next := i + 1 + cleanup
	if next < len(insts) {
		n := insts[next]
		if len(n.Labels) == 0 && n.Mnem == "mov" && len(n.Ops) == 2 && isEAX(n.Ops[1]) {
			e.emit(e.indent, "%s = %s;", e.dst(n.Ops, 0), call)
			e.dropPending(canonReg(lowOp(n.Ops, 0)))
			return cleanup + 1
		}
	}
	e.emit(e.indent, "%s;", call) // result unused
	return cleanup
}

// argCount decides how many arguments a call takes and how many following
// cleanup instructions to skip: `add esp, N` => N/4 args (caller-cleaned cdecl);
// a run of `pop ecx/edx` => one arg each; otherwise every pending push is an
// argument (callee-cleaned stdcall, e.g. an imported API).
func (e *emitter) argCount(insts []Inst, i int) (argc, cleanup int) {
	j := i + 1
	if j < len(insts) && len(insts[j].Labels) == 0 {
		n := insts[j]
		if n.Mnem == "add" && len(n.Ops) == 2 && isESP(n.Ops[0]) {
			return int(parseSignedImm(n.Ops[1]) / ptrSize), 1
		}
	}
	for j < len(insts) && len(insts[j].Labels) == 0 &&
		insts[j].Mnem == "pop" && isScratchReg(lowOp(insts[j].Ops, 0)) {
		cleanup++
		j++
	}
	if cleanup > 0 {
		return cleanup, cleanup
	}
	return len(e.pushes), 0
}

// takeArgs pops argc arguments off the pending pushes (LIFO) and returns them in
// call order (arguments are pushed right-to-left, so reverse). An IDA push
// comment that names a known frame variable is preferred over the raw operand.
func (e *emitter) takeArgs(argc int) []string {
	if argc > len(e.pushes) {
		argc = len(e.pushes)
	}
	if argc < 0 {
		argc = 0
	}
	taken := e.pushes[len(e.pushes)-argc:]
	out := make([]string, argc)
	for k := range taken {
		a := taken[argc-1-k]
		s := a.expr
		if isIdent(a.comment) {
			if _, ok := e.f.varByName(a.comment); ok {
				s = a.comment
			}
		}
		out[k] = s
	}
	return out
}

func (e *emitter) dropCallerSaved() {
	for _, r := range []string{"eax", "ecx", "edx"} {
		e.dropPending(r)
	}
}

// ---- conditions --------------------------------------------------------------

// condition turns the last cmp/test plus a conditional-jump mnemonic into a C
// boolean, falling back to a commented raw mnemonic if no compare preceded it.
func (e *emitter) condition(jcc string) string {
	c := e.lastCmp
	if c == nil {
		return "/* " + jcc + " */ 1"
	}
	if c.kind == "test" {
		lhs := c.a
		if c.a != c.b {
			lhs = fmt.Sprintf("(%s & %s)", c.a, c.b)
		}
		switch jcc {
		case "jz", "je":
			return lhs + " == 0"
		case "jnz", "jne":
			return lhs + " != 0"
		case "js":
			return lhs + " < 0"
		case "jns":
			return lhs + " >= 0"
		}
		return fmt.Sprintf("/* %s */ %s", jcc, lhs)
	}
	if op, ok := cmpOp(jcc); ok {
		return fmt.Sprintf("%s %s %s", c.a, op, c.b)
	}
	return fmt.Sprintf("/* %s */ %s, %s", jcc, c.a, c.b)
}

// negatedCondition renders the condition for the not-taken edge, used when a
// forward branch skips over an if-body.
func (e *emitter) negatedCondition(jcc string) string {
	if n := negateJcc(jcc); n != "" {
		return e.condition(n)
	}
	return "!(" + e.condition(jcc) + ")"
}

func cmpOp(jcc string) (string, bool) {
	switch jcc {
	case "jz", "je":
		return "==", true
	case "jnz", "jne":
		return "!=", true
	case "jl", "jnge", "jb", "jnae", "jc":
		return "<", true
	case "jle", "jng", "jbe", "jna":
		return "<=", true
	case "jg", "jnle", "ja", "jnbe":
		return ">", true
	case "jge", "jnl", "jae", "jnb", "jnc":
		return ">=", true
	}
	return "", false
}

func negateJcc(jcc string) string {
	switch jcc {
	case "jz", "je":
		return "jnz"
	case "jnz", "jne":
		return "jz"
	case "js":
		return "jns"
	case "jns":
		return "js"
	case "jl", "jnge":
		return "jge"
	case "jge", "jnl":
		return "jl"
	case "jle", "jng":
		return "jg"
	case "jg", "jnle":
		return "jle"
	case "jb", "jnae", "jc":
		return "jae"
	case "jae", "jnb", "jnc":
		return "jb"
	case "jbe", "jna":
		return "ja"
	case "ja", "jnbe":
		return "jbe"
	}
	return ""
}

// ---- operand rendering -------------------------------------------------------

// read renders operand n in a value (source) position, substituting a deferred
// register load.
func (e *emitter) read(ops []string, n int) string { return e.readSized(ops, n, 0) }

func (e *emitter) readSized(ops []string, n, hint int) string {
	if n >= len(ops) {
		return ""
	}
	op := strings.TrimSpace(ops[n])
	if isReg(strings.ToLower(op)) {
		return e.valOf(strings.ToLower(op))
	}
	return e.renderSized(op, hint)
}

// dst renders operand n in a destination position (no register substitution).
func (e *emitter) dst(ops []string, n int) string { return e.dstSized(ops, n, 0) }

func (e *emitter) dstSized(ops []string, n, hint int) string {
	if n >= len(ops) {
		return ""
	}
	op := strings.TrimSpace(ops[n])
	if isReg(strings.ToLower(op)) {
		return strings.ToLower(op)
	}
	return e.renderSized(op, hint)
}

func (e *emitter) render(op string) string { return e.renderSized(op, 0) }

func (e *emitter) renderSized(op string, hint int) string {
	op = strings.TrimSpace(op)
	low := strings.ToLower(op)
	if isReg(low) {
		return low
	}
	for _, p := range []string{"short ", "near ptr ", "far ptr ", "large ", "small "} {
		op = strings.TrimPrefix(op, p)
	}
	if strings.HasPrefix(op, "offset ") {
		return "&" + strings.TrimSpace(op[len("offset "):])
	}
	size := 0
	for _, sp := range []struct {
		pfx string
		sz  int
	}{{"byte ptr ", 1}, {"word ptr ", 2}, {"dword ptr ", 4}, {"qword ptr ", 8}, {"xmmword ptr ", 16}, {"tbyte ptr ", 10}} {
		if strings.HasPrefix(op, sp.pfx) {
			size = sp.sz
			op = strings.TrimSpace(op[len(sp.pfx):])
			break
		}
	}
	for _, seg := range []string{"ds:", "cs:", "es:", "ss:", "fs:", "gs:"} {
		if strings.HasPrefix(op, seg) {
			op = op[len(seg):]
			break
		}
	}
	if size == 0 {
		size = hint
	}
	if strings.HasPrefix(op, "[") && strings.HasSuffix(op, "]") {
		return e.renderMem(op[1:len(op)-1], size)
	}
	if imm, ok := renderImm(op); ok {
		return imm
	}
	return op
}

// renderMem renders the inside of a `[...]` operand. An ebp/esp-relative slot is
// a named frame variable; anything through a general register is a pointer
// dereference. Index registers are never substituted, so loop variables stay
// visible.
func (e *emitter) renderMem(inner string, size int) string {
	terms := splitAddr(inner)
	var regs []string
	var disp string
	for _, t := range terms {
		body := strings.TrimSpace(t.text)
		if isReg(strings.ToLower(body)) {
			regs = append(regs, t.sign+strings.ToLower(body))
			continue
		}
		disp = t.sign + body
	}
	if len(regs) == 1 {
		base := strings.TrimPrefix(regs[0], "+")
		if base == "ebp" || base == "esp" {
			if disp == "" {
				return base
			}
			name := strings.TrimPrefix(disp, "+")
			if isIdent(name) && !isNumericImm(name) {
				return name
			}
			off := parseSignedImm(disp)
			if off < 0 {
				return fmt.Sprintf("local_%X", -off)
			}
			if v, ok := frameByOff(e.f, off); ok {
				return v
			}
			return fmt.Sprintf("arg_%X", off)
		}
	}
	expr := joinAddr(regs, disp)
	switch size {
	case 1:
		return "*(char *)(" + expr + ")"
	case 2:
		return "*(short *)(" + expr + ")"
	default:
		if len(regs) == 1 && disp == "" {
			return "*" + strings.TrimPrefix(regs[0], "+")
		}
		return "*(" + expr + ")"
	}
}

// leaSource renders the address an lea computes (no dereference).
func (e *emitter) leaSource(ops []string) string {
	if len(ops) < 2 {
		return ""
	}
	op := strings.TrimSpace(ops[1])
	if strings.HasPrefix(op, "[") && strings.HasSuffix(op, "]") {
		m := e.renderMem(op[1:len(op)-1], 0)
		switch {
		case strings.HasPrefix(m, "*("):
			return strings.TrimSuffix(strings.TrimPrefix(m, "*("), ")")
		case strings.HasPrefix(m, "*"):
			return strings.TrimPrefix(m, "*")
		default:
			return "&" + m // a named frame slot: &var_81C
		}
	}
	return e.render(op)
}

func (e *emitter) callee(ops []string) string {
	if len(ops) == 0 {
		return "sub_unknown"
	}
	t := strings.TrimSpace(ops[0])
	for _, seg := range []string{"ds:", "cs:", "large "} {
		t = strings.TrimPrefix(t, seg)
	}
	if isReg(strings.ToLower(t)) {
		return "(*" + strings.ToLower(t) + ")"
	}
	t = strings.TrimPrefix(t, "__imp_")
	t = strings.TrimPrefix(t, "_imp_")
	if i := strings.IndexByte(t, '@'); i > 0 {
		t = t[:i]
	}
	return t
}

// ---- lexical helpers ---------------------------------------------------------

func renderImm(tok string) (string, bool) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", false
	}
	if strings.HasPrefix(tok, "0x") || strings.HasPrefix(tok, "0X") {
		return tok, true
	}
	if strings.HasSuffix(tok, "h") {
		if v, err := strconv.ParseUint(strings.TrimSuffix(tok, "h"), 16, 64); err == nil {
			return fmt.Sprintf("0x%X", v), true
		}
		return "", false
	}
	if _, err := strconv.ParseInt(tok, 10, 64); err == nil {
		return tok, true
	}
	return "", false
}

type addrTerm struct{ sign, text string }

// splitAddr splits a memory expression into signed terms: "ebp+var_18" ->
// [{+ ebp} {+ var_18}], "ebp-19h" -> [{+ ebp} {- 19h}].
func splitAddr(s string) []addrTerm {
	var terms []addrTerm
	sign := "+"
	start := 0
	flush := func(end int) {
		if t := strings.TrimSpace(s[start:end]); t != "" {
			terms = append(terms, addrTerm{sign: sign, text: t})
		}
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '+' || s[i] == '-' {
			flush(i)
			sign = string(s[i])
			start = i + 1
		}
	}
	flush(len(s))
	return terms
}

func joinAddr(regs []string, disp string) string {
	var parts []string
	for k, r := range regs {
		if k == 0 {
			parts = append(parts, strings.TrimPrefix(r, "+"))
		} else {
			parts = append(parts, r)
		}
	}
	if disp != "" {
		parts = append(parts, disp)
	}
	out := ""
	for k, p := range parts {
		if k == 0 {
			out = strings.TrimPrefix(p, "+")
			continue
		}
		if strings.HasPrefix(p, "-") {
			out += " - " + strings.TrimPrefix(p, "-")
		} else {
			out += " + " + strings.TrimPrefix(p, "+")
		}
	}
	return out
}

func frameByOff(f *Func, off int64) (string, bool) {
	for _, v := range f.Vars {
		if v.Off == off {
			return v.Name, true
		}
	}
	return "", false
}

// ---- callee denoise ----------------------------------------------------------

const (
	noiseNone = iota
	noiseGuard
	noiseSEHProlog
	noiseSEHEpilog
)

func classifyCallee(name string) int {
	switch {
	case strings.Contains(name, "guard_check_icall"), strings.Contains(name, "guard_dispatch_icall"):
		return noiseGuard
	case strings.Contains(name, "SEH_prolog"):
		return noiseSEHProlog
	case strings.Contains(name, "SEH_epilog"):
		return noiseSEHEpilog
	}
	return noiseNone
}

// ---- register tables ---------------------------------------------------------

var reg32 = map[string]bool{"eax": true, "ebx": true, "ecx": true, "edx": true, "esi": true, "edi": true, "ebp": true, "esp": true}
var reg16 = map[string]bool{"ax": true, "bx": true, "cx": true, "dx": true, "si": true, "di": true, "bp": true, "sp": true}
var reg8 = map[string]bool{"al": true, "bl": true, "cl": true, "dl": true, "ah": true, "bh": true, "ch": true, "dh": true}

func isReg(s string) bool { return reg32[s] || reg16[s] || reg8[s] }
func isR32(s string) bool { return reg32[s] }

func regSizeOf(s string) int {
	switch {
	case reg32[s]:
		return 4
	case reg16[s]:
		return 2
	case reg8[s]:
		return 1
	}
	return 0
}

func canonReg(s string) string {
	switch s {
	case "al", "ah", "ax":
		return "eax"
	case "bl", "bh", "bx":
		return "ebx"
	case "cl", "ch", "cx":
		return "ecx"
	case "dl", "dh", "dx":
		return "edx"
	case "si":
		return "esi"
	case "di":
		return "edi"
	case "bp":
		return "ebp"
	case "sp":
		return "esp"
	}
	return s
}

func isEAX(s string) bool { return strings.EqualFold(strings.TrimSpace(s), "eax") }
func isESP(s string) bool { return strings.EqualFold(strings.TrimSpace(s), "esp") }

func isScratchReg(s string) bool { return s == "ecx" || s == "edx" }

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		switch {
		case c == '_', c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z':
		case i > 0 && c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

func isNumericImm(s string) bool {
	_, ok := renderImm(s)
	return ok
}

func lowOp(ops []string, n int) string {
	if n >= len(ops) {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(ops[n]))
}

// skipPrologue advances past a standard MSVC prologue: push ebp / mov ebp, esp /
// sub esp, N / and a run of callee-saved register pushes.
func (e *emitter) skipPrologue(insts []Inst, i int) int {
	n := len(insts)
	if i < n && insts[i].Mnem == "push" && lowOp(insts[i].Ops, 0) == "ebp" && len(insts[i].Labels) == 0 {
		i++
		if i < n && insts[i].Mnem == "mov" && lowOp(insts[i].Ops, 0) == "ebp" {
			i++
		}
		if i < n && insts[i].Mnem == "sub" && lowOp(insts[i].Ops, 0) == "esp" {
			i++
		}
		for i < n && insts[i].Mnem == "push" && isReg(lowOp(insts[i].Ops, 0)) && len(insts[i].Labels) == 0 {
			i++
		}
	}
	return i
}
