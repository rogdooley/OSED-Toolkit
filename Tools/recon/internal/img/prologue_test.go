package img

import "testing"

func TestScanProloguesSeedsFramePointerFunctions(t *testing.T) {
	// Two prologues in a code segment at VA 0x401000:
	//   +0x00: 55 8B EC            push ebp; mov ebp,esp
	//   +0x08: 8B FF 55 8B EC      mov edi,edi; push ebp; mov ebp,esp (hot-patch)
	code := []byte{
		0x55, 0x8B, 0xEC, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0xC3,
	}
	im := &Image{
		Bits:      32,
		ImageBase: 0x00400000,
		iat:       map[uint64]string{},
		syms:      map[uint64]string{},
		segs:      []segment{{va: 0x00401000, data: code, exec: true}},
	}
	im.scanPrologues()

	got := map[uint64]bool{}
	for _, s := range im.seeds {
		got[s] = true
	}
	if !got[0x00401000] {
		t.Error("missing seed for plain prologue at 0x401000")
	}
	// Hot-patch: true start is at the mov edi,edi (0x401008), not the push ebp.
	if !got[0x00401008] {
		t.Errorf("hot-patch prologue should seed at 0x401008, seeds=%v", im.seeds)
	}
}

func TestScanProloguesSkipsDataSections(t *testing.T) {
	code := []byte{0x55, 0x8B, 0xEC}
	im := &Image{
		Bits: 32, ImageBase: 0x00400000,
		iat: map[uint64]string{}, syms: map[uint64]string{},
		segs: []segment{{va: 0x00402000, data: code, exec: false}},
	}
	im.scanPrologues()
	if len(im.seeds) != 0 {
		t.Fatalf("prologue bytes in a data section must not seed: %v", im.seeds)
	}
}
