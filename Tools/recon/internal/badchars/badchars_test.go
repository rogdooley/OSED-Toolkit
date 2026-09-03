package badchars

import "testing"

func TestParseSpecFormats(t *testing.T) {
	want := []byte{0x00, 0x0a, 0x0d}
	for _, in := range []string{`\x00\x0a\x0d`, "00 0a 0d", "0x00,0x0a,0x0d", "000a0d", "00\t0a\n0d"} {
		got, err := ParseSpec(in)
		if err != nil {
			t.Fatalf("ParseSpec(%q): %v", in, err)
		}
		if len(got) != len(want) {
			t.Fatalf("ParseSpec(%q) = %v, want %v", in, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("ParseSpec(%q) = %v, want %v", in, got, want)
			}
		}
	}
	if _, err := ParseSpec("0a0"); err == nil {
		t.Fatal("odd-length spec should error")
	}
}

func TestCleanChecksLowBytes(t *testing.T) {
	bad := []byte{0x00, 0x0a, 0x0d}
	// 0x625011af -> bytes af 11 50 62, none bad -> clean.
	if ok, _, _ := Clean(0x625011af, bad, 32); !ok {
		t.Fatal("0x625011af should be clean of 00/0a/0d")
	}
	// 0x62500a10 -> byte 0x0a present -> not clean, at position 1.
	ok, b, pos := Clean(0x62500a10, bad, 32)
	if ok || b != 0x0a || pos != 1 {
		t.Fatalf("Clean(0x62500a10) = %v,0x%02x,%d; want false,0x0a,1", ok, b, pos)
	}
	// A null byte in the high byte (0x0040f8c3 -> byte3 0x00) is caught too.
	if ok, _, _ := Clean(0x0040f8c3, bad, 32); ok {
		t.Fatal("0x0040f8c3 has a null byte and should be flagged")
	}
}

func TestExtractAddrForms(t *testing.T) {
	cases := map[string]uint64{
		"0x625011af: pop eax ; ret":         0x625011af,
		"625011af 58              pop eax":  0x625011af,
		"00000000`625011af  ff e4  jmp esp": 0x625011af,
		"0x77bef8c3 : # pop pop ret":        0x77bef8c3,
	}
	for line, want := range cases {
		got, ok := ExtractAddr(line)
		if !ok || got != want {
			t.Fatalf("ExtractAddr(%q) = 0x%x,%v; want 0x%x", line, got, ok, want)
		}
	}
	if _, ok := ExtractAddr("pop eax ; ret"); ok {
		t.Fatal("line with no address should not extract one")
	}
}
