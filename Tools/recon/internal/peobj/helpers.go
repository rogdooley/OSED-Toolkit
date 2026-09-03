package peobj

import (
	"bytes"
	"fmt"
	"math"
	"time"
)

func lookup(m map[uint16]string, k uint16) string {
	if v, ok := m[k]; ok {
		return v
	}
	return fmt.Sprintf("0x%04X", k)
}

func version(maj, min uint8) string { return fmt.Sprintf("%d.%d", maj, min) }

func formatTimestamp(ts uint32) string {
	if ts == 0 || ts == 0xFFFFFFFF {
		return fmt.Sprintf("0x%08X", ts)
	}
	return time.Unix(int64(ts), 0).UTC().Format("2006-01-02 15:04:05 UTC")
}

func entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	e := 0.0
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		e -= p * math.Log2(p)
	}
	return e
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

func count(data, pat []byte) int {
	n, start := 0, 0
	for {
		i := bytes.Index(data[start:], pat)
		if i < 0 {
			break
		}
		n++
		start += i + 1
	}
	return n
}

// countAddEspRet counts `add esp, imm8; ret` (83 C4 ib C3) and
// `add esp, imm32; ret` (81 C4 id C3) sequences.
func countAddEspRet(data []byte) int {
	n := 0
	for i := 0; i+3 < len(data); i++ {
		if data[i] == 0x83 && data[i+1] == 0xC4 && data[i+3] == 0xC3 {
			n++
		}
	}
	for i := 0; i+6 < len(data); i++ {
		if data[i] == 0x81 && data[i+1] == 0xC4 && data[i+6] == 0xC3 {
			n++
		}
	}
	return n
}

func bytesContains(hay, needle []byte) bool { return bytes.Contains(hay, needle) }

func interestingStrings(raw []byte) []string {
	strs := extractASCII(raw, 4)
	seen := map[string]bool{}
	var out []string
	for _, s := range strs {
		ls := toLower(s)
		for _, p := range interestingPatterns {
			if contains(ls, p) {
				if !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
				break
			}
		}
		if len(out) >= 200 {
			break
		}
	}
	return out
}

func extractASCII(data []byte, minLen int) []string {
	var out []string
	var cur []byte
	flush := func() {
		if len(cur) >= minLen {
			out = append(out, string(cur))
		}
		cur = cur[:0]
	}
	for _, b := range data {
		if b >= 0x20 && b < 0x7F {
			cur = append(cur, b)
		} else {
			flush()
		}
	}
	flush()
	return out
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

func itoaReason(n int, label string) string { return fmt.Sprintf("%d %s", n, label) }
