package disasm

import (
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// fakeImg satisfies the CStringAt interface stringRefs expects.
type fakeImg struct{ at map[uint64]string }

func (f fakeImg) CStringAt(va uint64) (string, bool) {
	s, ok := f.at[va]
	return s, ok
}

// push 0x00403000  ->  68 00 30 40 00 ; resolves to a string pointer.
func TestStringRefsDetectsPushedString(t *testing.T) {
	code := []byte{0x68, 0x00, 0x30, 0x40, 0x00}
	inst, err := x86asm.Decode(code, 32)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	im := fakeImg{at: map[uint64]string{0x00403000: "%s logged in"}}
	refs, isStr := stringRefs(im, inst)
	if !isStr || len(refs) != 1 || refs[0] != "%s logged in" {
		t.Fatalf("stringRefs = %v, %v; want [\"%%s logged in\"], true", refs, isStr)
	}
}

// mov eax, 0x00403000  ->  B8 00 30 40 00 ; string ref but not a push.
func TestStringRefsNonPushStillResolves(t *testing.T) {
	code := []byte{0xB8, 0x00, 0x30, 0x40, 0x00}
	inst, err := x86asm.Decode(code, 32)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	im := fakeImg{at: map[uint64]string{0x00403000: "kernel32.dll"}}
	refs, isStr := stringRefs(im, inst)
	if len(refs) != 1 || refs[0] != "kernel32.dll" {
		t.Fatalf("refs = %v; want [\"kernel32.dll\"]", refs)
	}
	if inst.Op == x86asm.PUSH {
		t.Fatal("mov decoded as PUSH?")
	}
	_ = isStr
}
