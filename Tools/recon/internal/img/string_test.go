package img

import "testing"

func TestCStringAtReadsDataStringButNotCode(t *testing.T) {
	const base = 0x00400000
	// A data segment at 0x403000 holding "GET / HTTP\0".
	data := append([]byte("GET / HTTP"), 0)
	im := &Image{
		Bits:      32,
		ImageBase: base,
		iat:       map[uint64]string{},
		syms:      map[uint64]string{},
		segs: []segment{
			{va: 0x00403000, data: data, exec: false},
			{va: 0x00401000, data: append([]byte("also/text"), 0), exec: true},
		},
	}

	if s, ok := im.CStringAt(0x00403000); !ok || s != "GET / HTTP" {
		t.Fatalf("CStringAt(data) = %q, %v; want \"GET / HTTP\", true", s, ok)
	}
	// Executable section: printable bytes must NOT be reported as a string.
	if s, ok := im.CStringAt(0x00401000); ok {
		t.Fatalf("CStringAt(exec) = %q, true; want no string in code", s)
	}
	// Too short (<4 printable before NUL).
	short := append([]byte("hi"), 0)
	im.segs = append(im.segs, segment{va: 0x00404000, data: short, exec: false})
	if _, ok := im.CStringAt(0x00404000); ok {
		t.Fatal("CStringAt short string should fail")
	}
}
