package analysis

import "fmt"

func frameReason(n int64) string {
	return fmt.Sprintf("large stack frame (0x%X bytes) - room for an overflowable buffer", n)
}
