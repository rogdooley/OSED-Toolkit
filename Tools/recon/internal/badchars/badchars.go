// Package badchars parses a bad-character specification and checks whether an
// address is free of those bytes. It exists to fill the one gap in an external
// gadget finder (osed-windb): filtering gadgets whose ADDRESS contains a byte
// you cannot send (0x00, 0x0a, 0x0d, and target-specific ones).
package badchars

import (
	"fmt"
	"strings"
)

// ParseSpec parses a bad-character list. It is liberal about format and accepts
// any mix of these, with or without separators:
//
//	\x00\x0a\x0d      00 0a 0d      0x00,0x0a,0x0d      000a0d
//
// Returned bytes are de-duplicated. An odd number of hex digits is an error.
func ParseSpec(s string) ([]byte, error) {
	r := strings.NewReplacer(
		`\x`, "", "0x", "", "0X", "",
		",", "", " ", "", "\t", "", "\n", "", "\r", "", ";", "", "|", "",
	)
	clean := r.Replace(s)
	if clean == "" {
		return nil, nil
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("bad-char spec has an odd number of hex digits: %q", s)
	}
	seen := map[byte]bool{}
	var out []byte
	for i := 0; i < len(clean); i += 2 {
		var v int
		if _, err := fmt.Sscanf(clean[i:i+2], "%x", &v); err != nil {
			return nil, fmt.Errorf("invalid hex byte %q in bad-char spec", clean[i:i+2])
		}
		b := byte(v)
		if !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	return out, nil
}

// Clean reports whether addr contains none of the bad bytes across its low
// bits/8 bytes. When it is not clean, it also returns the lowest-position
// offending byte and that position (0 = least-significant byte).
func Clean(addr uint64, bad []byte, bits int) (ok bool, offend byte, pos int) {
	n := bits / 8
	if n == 0 {
		n = 4
	}
	set := [256]bool{}
	for _, b := range bad {
		set[b] = true
	}
	for i := 0; i < n; i++ {
		b := byte(addr >> (8 * i))
		if set[b] {
			return false, b, i
		}
	}
	return true, 0, 0
}
