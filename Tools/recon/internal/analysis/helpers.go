package analysis

import "fmt"

func frameReason(n int64) string {
	return fmt.Sprintf("large stack frame (0x%X bytes) - room for an overflowable buffer", n)
}

// frameBonus scales the score with stack-frame size. Frames under 0x80 carry no
// signal (too small to hold an interesting overflow buffer, and ubiquitous), so
// they do not flood the ranking of a statically-linked binary.
func frameBonus(n int64) int {
	switch {
	case n >= 0x800:
		return 5
	case n >= 0x400:
		return 4
	case n >= 0x200:
		return 3
	case n >= 0x100:
		return 2
	case n >= 0x80:
		return 1
	}
	return 0
}
