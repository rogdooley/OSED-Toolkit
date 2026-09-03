package img

import (
	"debug/pe"
	"encoding/binary"
	"testing"
)

// TestLoadImportsResolvesIATSlot builds a synthetic 32-bit import directory in
// one segment and checks that loadImports maps the IAT slot VA to the imported
// name. This exercises the descriptor walk, INT thunk decode, and
// IMAGE_IMPORT_BY_NAME string read without needing a real binary on disk.
func TestLoadImportsResolvesIATSlot(t *testing.T) {
	const base = 0x00400000
	buf := make([]byte, 0x80) // covers RVA 0x1000..0x1080
	put32 := func(rva uint32, v uint32) { binary.LittleEndian.PutUint32(buf[rva-0x1000:], v) }

	// Import descriptor at RVA 0x1000.
	put32(0x1000, 0x1028) // OriginalFirstThunk (INT rva)
	put32(0x100C, 0x1040) // Name rva
	put32(0x1010, 0x1050) // FirstThunk (IAT rva)
	// Terminator descriptor (20 zero bytes) at 0x1014 is already zero.

	// INT at 0x1028: one entry pointing to IMAGE_IMPORT_BY_NAME at 0x1060.
	put32(0x1028, 0x1060)
	// terminator at 0x102C already zero.

	// DLL name at 0x1040.
	copy(buf[0x1040-0x1000:], append([]byte("TEST.dll"), 0))

	// IAT at 0x1050 mirrors the INT (bound-import shape not needed here).
	put32(0x1050, 0x1060)

	// IMAGE_IMPORT_BY_NAME at 0x1060: 2-byte hint then "strcpy\0".
	copy(buf[0x1062-0x1000:], append([]byte("strcpy"), 0))

	im := &Image{
		Bits:      32,
		ImageBase: base,
		iat:       map[uint64]string{},
		syms:      map[uint64]string{},
		segs:      []segment{{va: base + 0x1000, data: buf, exec: false}},
	}
	dd := make([]pe.DataDirectory, 16)
	dd[1] = pe.DataDirectory{VirtualAddress: 0x1000, Size: 40}

	im.loadImports(dd)

	slot := uint64(base + 0x1050)
	got, ok := im.APIAt(slot)
	if !ok || got != "strcpy" {
		t.Fatalf("APIAt(0x%X) = %q, %v; want \"strcpy\", true (iat=%v)", slot, got, ok, im.iat)
	}
}
