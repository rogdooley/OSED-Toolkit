package disasm

import (
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestByteCmpImm(t *testing.T) {
	cases := []struct {
		name string
		code []byte
		want byte
		ok   bool
	}{
		{"cmp al,0Ah", []byte{0x3C, 0x0A}, 0x0A, true},
		{"cmp cl,25h", []byte{0x80, 0xF9, 0x25}, 0x25, true},
		{"cmp byte[eax],0Dh", []byte{0x80, 0x38, 0x0D}, 0x0D, true},
		{"cmp eax,0Ah (wide, reject)", []byte{0x3D, 0x0A, 0x00, 0x00, 0x00}, 0, false},
		{"mov al,0Ah (not cmp)", []byte{0xB0, 0x0A}, 0, false},
	}
	for _, c := range cases {
		in, err := x86asm.Decode(c.code, 32)
		if err != nil {
			t.Fatalf("%s: decode: %v", c.name, err)
		}
		got, ok := byteCmpImm(in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%s: byteCmpImm = 0x%02x,%v; want 0x%02x,%v", c.name, got, ok, c.want, c.ok)
		}
	}
}
