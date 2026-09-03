package disasm

import (
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// call dword ptr [0x00402000]  ->  FF 15 00 20 40 00
func TestMemAbsResolvesIATCall(t *testing.T) {
	code := []byte{0xFF, 0x15, 0x00, 0x20, 0x40, 0x00}
	inst, err := x86asm.Decode(code, 32)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if inst.Op != x86asm.CALL {
		t.Fatalf("op = %v, want CALL", inst.Op)
	}
	abs, ok := memAbs(inst, 32)
	if !ok || abs != 0x00402000 {
		t.Fatalf("memAbs = 0x%X, %v; want 0x402000, true", abs, ok)
	}
}

// call rel32 from VA 0x401000: E8 <rel> where target = 0x401005 + rel.
// Encode a call to 0x401234: rel = 0x401234 - 0x401005 = 0x22F.
func TestRelTargetResolvesDirectCall(t *testing.T) {
	code := []byte{0xE8, 0x2F, 0x02, 0x00, 0x00}
	inst, err := x86asm.Decode(code, 32)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	tgt, ok := relTarget(inst, 0x401000)
	if !ok || tgt != 0x401234 {
		t.Fatalf("relTarget = 0x%X, %v; want 0x401234, true", tgt, ok)
	}
}

// sub esp, 0x400  ->  81 EC 00 04 00 00
func TestEspFrameDetectsPrologue(t *testing.T) {
	code := []byte{0x81, 0xEC, 0x00, 0x04, 0x00, 0x00}
	inst, err := x86asm.Decode(code, 32)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	fs, ok := espFrame(inst, 32)
	if !ok || fs != 0x400 {
		t.Fatalf("espFrame = 0x%X, %v; want 0x400, true", fs, ok)
	}
}

// jmp dword ptr [0x00402008]  ->  FF 25 08 20 40 00  (an IAT thunk)
func TestThunkJmpIsMem(t *testing.T) {
	code := []byte{0xFF, 0x25, 0x08, 0x20, 0x40, 0x00}
	inst, err := x86asm.Decode(code, 32)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if inst.Op != x86asm.JMP {
		t.Fatalf("op = %v, want JMP", inst.Op)
	}
	abs, ok := memAbs(inst, 32)
	if !ok || abs != 0x00402008 {
		t.Fatalf("memAbs = 0x%X, %v; want 0x402008, true", abs, ok)
	}
}
