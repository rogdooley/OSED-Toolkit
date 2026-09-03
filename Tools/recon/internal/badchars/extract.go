package badchars

import (
	"regexp"
	"strings"
)

// Address forms seen in gadget dumps, in preference order:
//   - WinDbg 64-bit: 00000000`625011af
//   - explicit hex:  0x625011af
//   - bare 32-bit:   625011af   (WinDbg `u`, rp++, mona style at line start)
var addrForms = []*regexp.Regexp{
	regexp.MustCompile(`[0-9a-fA-F]{8}` + "`" + `[0-9a-fA-F]{8}`),
	regexp.MustCompile(`0x[0-9a-fA-F]{1,16}`),
	regexp.MustCompile(`\b[0-9a-fA-F]{8}\b`),
}

// ExtractAddr pulls the first address-looking token out of a line and parses
// it. The byte columns of a disassembly (2-hex groups like "58 c3") are too
// short to match the 8-hex forms, so the gadget address wins.
func ExtractAddr(line string) (uint64, bool) {
	best := -1
	var bestTok string
	for _, re := range addrForms {
		if loc := re.FindStringIndex(line); loc != nil {
			if best == -1 || loc[0] < best {
				best = loc[0]
				bestTok = line[loc[0]:loc[1]]
			}
		}
	}
	if best == -1 {
		return 0, false
	}
	tok := strings.NewReplacer("0x", "", "0X", "", "`", "").Replace(bestTok)
	var v uint64
	for _, c := range tok {
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, false
		}
		v = v<<4 | d
	}
	return v, true
}
