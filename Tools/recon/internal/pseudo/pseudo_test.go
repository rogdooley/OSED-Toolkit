package pseudo

import (
	"strings"
	"testing"
)

func emitOne(t *testing.T, listing string) string {
	t.Helper()
	funcs := Parse(strings.NewReader(listing))
	if len(funcs) != 1 {
		t.Fatalf("expected 1 function, got %d", len(funcs))
	}
	var b strings.Builder
	Emit(&b, funcs[0])
	return b.String()
}

// wantAll fails unless every substring is present, printing the output once.
func wantAll(t *testing.T, out string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(out, s) {
			t.Errorf("missing %q in:\n%s", s, out)
		}
	}
}

const threadListing = `
; DWORD __stdcall sub_14801040(LPVOID lpThreadParameter)
sub_14801040 proc near

var_81C= byte ptr -81Ch
var_1C= dword ptr -1Ch
buf= dword ptr -8
var_14= dword ptr -14h
var_C= dword ptr -0Ch
s= dword ptr  8

push    ebp
mov     ebp, esp
sub     esp, 81Ch
push    ebx
push    840h
call    sub_14801247
add     esp, 4
mov     [ebp+var_18], eax
mov     eax, [ebp+var_18]
mov     [ebp+buf], eax
push    840h
push    0
mov     ecx, [ebp+buf]
push    ecx
call    sub_148020A0
add     esp, 0Ch
push    800h
push    11h
lea     edx, [ebp+var_81C]
push    edx
call    sub_148020A0
add     esp, 0Ch
push    0               ; flags
push    830h            ; len
mov     eax, [ebp+buf]
push    eax             ; buf
mov     ecx, [ebp+s]
push    ecx             ; s
call    ds:recv
mov     [ebp+var_14], eax
mov     edx, [ebp+s]
push    edx             ; s
call    ds:closesocket
mov     [ebp+var_C], 0
retn
sub_14801040 endp
`

func TestThreadRecvReconstruction(t *testing.T) {
	out := emitOne(t, threadListing)
	wantAll(t, out,
		"DWORD __stdcall sub_14801040(int s)",
		"stack buffers: var_81C[0x800]",
		"var_18 = sub_14801247(0x840);", // cdecl result folds into the store
		"buf = var_18;",                 // deferred load, no stray `eax =`
		"sub_148020A0(buf, 0, 0x840);",  // register arg shows the variable
		"sub_148020A0(&var_81C, 0x11, 0x800);",
		"recv(s, buf, 0x830, 0)", // stdcall args; comments name s/buf, not len/flags
		"closesocket(s);",
	)
	// The `len`/`flags` push comments must NOT be used as argument values.
	if strings.Contains(out, "recv(s, buf, len, flags") {
		t.Errorf("push comments leaked as argument values:\n%s", out)
	}
	// Register loads that get consumed must not linger as their own statements.
	if strings.Contains(out, "ecx = buf;") || strings.Contains(out, "eax = var_18;") {
		t.Errorf("deferred register load was not consumed:\n%s", out)
	}
}

const strcpyListing = `
.text:14801000 sub_14801000    proc near
.text:14801000 arg_0           = dword ptr  8
.text:14801000 arg_4           = dword ptr  0Ch
.text:14801000                 push    ebp
.text:14801001                 mov     ebp, esp
.text:14801003                 push    esi
.text:1480100B                 mov     esi, [ebp+arg_4]
.text:1480100E                 mov     edi, [ebp+arg_0]
.text:14801011                 xor     ecx, ecx
.text:14801013                 dec     ecx
.text:1480101A loc_1480101A:
.text:1480101A                 inc     ecx
.text:1480101B                 mov     al, [esi+ecx]
.text:1480101E                 cmp     al, 0
.text:14801020                 jnz     short loc_1480101A
.text:14801022                 mov     eax, ecx
.text:14801024                 dec     edx
.text:14801025 loc_14801025:
.text:14801025                 inc     edx
.text:14801026                 mov     bl, [esi+edx]
.text:14801029                 mov     [edi+edx], bl
.text:1480102C                 cmp     edx, eax
.text:1480102E                 jnz     short loc_14801025
.text:14801038                 retn    8
.text:14801038 sub_14801000    endp
`

func TestStrcpyLoopsAndCasts(t *testing.T) {
	out := emitOne(t, strcpyListing)
	wantAll(t, out,
		"esi = arg_4;",               // deferred load flushed before the loop
		"do {",                       // back-edge structured into do/while
		"al = *(char *)(esi + ecx);", // byte cast inferred from `al`
		"} while (al != 0);",         // self-loop cmp+jnz -> loop condition
		"*(char *)(edi + edx) = bl;", // memory-destination store
		"} while (edx != eax);",
	)
	// The back-edge labels and gotos must be gone (fully structured).
	if strings.Contains(out, "goto loc_1480101A") || strings.Contains(out, "loc_1480101A:") {
		t.Errorf("self-loop was not structured into do/while:\n%s", out)
	}
	// A loop counter must stay literal, never folded into a constant.
	if strings.Contains(out, "ecx + 1 + 1") {
		t.Errorf("loop induction variable was wrongly folded:\n%s", out)
	}
	// Frame teardown must not leak as a data assignment.
	if strings.Contains(out, "esp = ebp") {
		t.Errorf("epilogue `mov esp, ebp` leaked:\n%s", out)
	}
}

func TestIfThenStructuring(t *testing.T) {
	out := emitOne(t, `
sub_2 proc near
arg_0= dword ptr  8
arg_4= dword ptr  0Ch
push    ebp
mov     ebp, esp
mov     eax, [ebp+arg_0]
test    eax, eax
jz      short loc_done
mov     ecx, [ebp+arg_4]
mov     [ebp+var_4], ecx
loc_done:
xor     eax, eax
pop     ebp
retn
sub_2 endp
`)
	wantAll(t, out,
		"if (arg_0 != 0) {", // forward branch negated; eax's deferred load (arg_0) folds in
		"var_4 = arg_4;",    // then-body
		"}",
	)
	// The forward branch must be structured, not left as a goto.
	if strings.Contains(out, "goto loc_done") {
		t.Errorf("forward if was not structured:\n%s", out)
	}
}

func TestSharedLabelDegradesToGoto(t *testing.T) {
	// A back-edge target that a second branch also jumps to is NOT a clean
	// single-entry loop; it must stay as gotos rather than be mis-structured.
	out := emitOne(t, `
sub_3 proc near
loc_top:
inc     eax
cmp     eax, 5
jl      short loc_top
cmp     eax, 9
jz      short loc_top
retn
sub_3 endp
`)
	if strings.Contains(out, "do {") {
		t.Errorf("shared-entry loop was wrongly structured:\n%s", out)
	}
	wantAll(t, out, "goto loc_top;", "loc_top:")
}

func TestTailCallThunk(t *testing.T) {
	out := emitOne(t, `
.text:14801247 sub_14801247    proc near
.text:14801247                 push    ebp
.text:14801248                 mov     ebp, esp
.text:1480124A                 pop     ebp
.text:1480124B                 jmp     sub_14801486
.text:1480124B sub_14801247    endp
`)
	wantAll(t, out, "return sub_14801486(); // tail call")
}

func TestParseAddrPrefixAndFrameVars(t *testing.T) {
	funcs := Parse(strings.NewReader(strcpyListing))
	f := funcs[0]
	if f.Name != "sub_14801000" {
		t.Fatalf("name = %q", f.Name)
	}
	got := map[string]int64{}
	for _, v := range f.Vars {
		got[v.Name] = v.Off
	}
	if got["arg_0"] != 8 || got["arg_4"] != 0xC {
		t.Errorf("frame offsets wrong: %+v", got)
	}
	// The `.text:ADDR` prefix must have been stripped so instructions parse.
	if len(f.Insts) == 0 {
		t.Fatal("no instructions parsed from address-prefixed listing")
	}
}

func TestUTF8XrefArrowsTolerated(t *testing.T) {
	// IDA emits non-ASCII arrows in xref comments; they must not break parsing
	// and must not appear in output.
	out := emitOne(t, "sub_1 proc near\ncall    ds:recv         ; CODE XREF: foo↓j\nretn\nsub_1 endp\n")
	for _, r := range out {
		if r > 127 {
			t.Fatalf("non-ASCII rune in output: %q", out)
		}
	}
}

func TestGuardAndSEHDenoise(t *testing.T) {
	out := emitOne(t, `
sub_1 proc near
call    @_guard_check_icall_nop@4 ; _guard_check_icall_nop(x)
call    j_@_guard_check_icall_nop@4
push    14h
call    __SEH_prolog4
retn
sub_1 endp
`)
	if strings.Contains(out, "guard_check_icall") {
		t.Errorf("CFG guard check not denoised:\n%s", out)
	}
	wantAll(t, out, "// SEH prologue")
}

func TestConditionForms(t *testing.T) {
	out := emitOne(t, `
sub_1 proc near
test    eax, eax
jz      short loc_a
cmp     ebx, 5
jg      short loc_b
retn
sub_1 endp
`)
	wantAll(t, out, "if (eax == 0) goto loc_a;", "if (ebx > 5) goto loc_b;")
}
