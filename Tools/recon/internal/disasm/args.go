package disasm

import "golang.org/x/arch/x86/x86asm"

// relTarget returns the absolute target of a PC-relative instruction (its
// first Rel arg), if it has one.
func relTarget(inst x86asm.Inst, va uint64) (uint64, bool) {
	for _, a := range inst.Args {
		if a == nil {
			break
		}
		if rel, ok := a.(x86asm.Rel); ok {
			return va + uint64(inst.Len) + uint64(int64(rel)), true
		}
	}
	return 0, false
}

// memAbs returns the absolute address of a first memory operand that is a
// bare displacement (no base, no index) - i.e. `[0xADDR]`, the shape of a
// call/jmp through an IAT slot in a non-relocated image.
func memAbs(inst x86asm.Inst, bits int) (uint64, bool) {
	for _, a := range inst.Args {
		if a == nil {
			break
		}
		if m, ok := a.(x86asm.Mem); ok {
			if m.Base == 0 && m.Index == 0 && m.Disp != 0 {
				d := uint64(m.Disp)
				if bits == 32 {
					d &= 0xFFFFFFFF
				}
				return d, true
			}
			return 0, false
		}
	}
	return 0, false
}

// espFrame returns the frame size of a `sub esp/rsp, imm` prologue instruction.
func espFrame(inst x86asm.Inst, bits int) (int64, bool) {
	sp := x86asm.ESP
	if bits == 64 {
		sp = x86asm.RSP
	}
	if len(inst.Args) < 2 || inst.Args[0] == nil || inst.Args[1] == nil {
		return 0, false
	}
	reg, ok := inst.Args[0].(x86asm.Reg)
	if !ok || reg != sp {
		return 0, false
	}
	imm, ok := inst.Args[1].(x86asm.Imm)
	if !ok {
		return 0, false
	}
	v := int64(imm)
	if v < 0 {
		v = -v
	}
	return v, true
}

// stringRefs returns any printable strings referenced by an instruction's
// immediate or bare-displacement operands (push offset, lea, mov reg,imm). The
// second result reports whether at least one operand resolved to a string,
// used to recognize a pushed format-string argument.
func stringRefs(im interface {
	CStringAt(uint64) (string, bool)
}, inst x86asm.Inst) ([]string, bool) {
	var out []string
	for _, a := range inst.Args {
		if a == nil {
			break
		}
		var cand uint64
		switch v := a.(type) {
		case x86asm.Imm:
			cand = uint64(int64(v)) & 0xFFFFFFFF
		case x86asm.Mem:
			if v.Base != 0 || v.Index != 0 || v.Disp == 0 {
				continue
			}
			cand = uint64(v.Disp) & 0xFFFFFFFF
		default:
			continue
		}
		if s, ok := im.CStringAt(cand); ok {
			out = append(out, s)
		}
	}
	return out, len(out) > 0
}

const hexDigits = "0123456789abcdef"

func hex(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{hexDigits[v&0xF]}, b...)
		v >>= 4
	}
	return string(b)
}
