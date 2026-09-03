// Package analysis holds the frontend-independent function model and the
// ranking logic. Both the disasm frontend (static, x86asm) and the cdb
// frontend (text dump from a headless debugger) produce []Func and hand it to
// Rank, so the two paths always agree on how targets are scored.
package analysis

import (
	"sort"
	"strings"

	"osed/recon/internal/apis"
)

// Call is one call site inside a function. API is the resolved import name
// when the callee is (or thunks to) a known API, otherwise "".
type Call struct {
	Site   uint64 `json:"site"`   // VA of the call instruction (0 if unknown)
	Target uint64 `json:"target"` // resolved callee VA (0 if indirect/unknown)
	API    string `json:"api"`    // resolved API name, or ""
}

// Func is a discovered function plus the signals that make it worth reversing.
type Func struct {
	Start         uint64   `json:"start"`
	Name          string   `json:"name"`
	FrameSize     int64    `json:"frame_size"` // bytes from `sub esp, imm` prologue
	Calls         []Call   `json:"calls"`
	StringOps     bool     `json:"string_ops"`     // rep movs / rep stos present
	FormatDynamic bool     `json:"format_dynamic"` // format-family call with no constant format pushed
	Strings       []string `json:"strings"`        // referenced string literals
	Callers       int      `json:"callers"`        // number of functions that call this one
	ThunkAPI      string   `json:"thunk_api"`      // set if the function is just `jmp [IAT]`
	Score         int      `json:"score"`
	Reasons       []string `json:"reasons"`
}

// Rank scores every function and returns them sorted most-interesting first.
// Thunk functions (bare `jmp [IAT]`) are dropped from the ranked view. Before
// scoring, it computes which functions are reachable from an input-reading
// function through the call graph, so an unbounded copy in a callee still
// scores the overflow synergy even when the recv is in an ancestor.
func Rank(funcs []Func) []Func {
	reach := inputReachable(funcs)
	var out []Func
	for i := range funcs {
		f := funcs[i]
		if f.ThunkAPI != "" {
			continue
		}
		f.Score, f.Reasons = scoreFunc(&f, reach[f.Start])
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Start < out[j].Start
	})
	return out
}

// inputReachable returns the set of function start addresses that either read
// attacker input directly or are called (transitively) from one that does.
// It relies on Call.Target, so it is effective for the disasm frontend; the
// cdb frontend leaves Target zero and falls back to direct detection only.
func inputReachable(funcs []Func) map[uint64]bool {
	idx := make(map[uint64]int, len(funcs))
	for i := range funcs {
		if funcs[i].Start != 0 {
			idx[funcs[i].Start] = i
		}
	}
	reach := map[uint64]bool{}
	var q []uint64
	for i := range funcs {
		if funcs[i].Start == 0 {
			continue
		}
		for _, c := range funcs[i].Calls {
			if c.API != "" && apis.InputRead[c.API] {
				if !reach[funcs[i].Start] {
					reach[funcs[i].Start] = true
					q = append(q, funcs[i].Start)
				}
				break
			}
		}
	}
	for len(q) > 0 {
		s := q[len(q)-1]
		q = q[:len(q)-1]
		i, ok := idx[s]
		if !ok {
			continue
		}
		for _, c := range funcs[i].Calls {
			if c.Target != 0 && !reach[c.Target] {
				if _, ok := idx[c.Target]; ok {
					reach[c.Target] = true
					q = append(q, c.Target)
				}
			}
		}
	}
	return reach
}

func scoreFunc(f *Func, reachable bool) (int, []string) {
	var reasons []string
	score := 0

	var unbounded, bounded, reads []string
	hasFormat, hasExec := false, false
	seen := map[string]bool{}
	for _, c := range f.Calls {
		a := c.API
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		switch {
		case apis.UnboundedCopy[a]:
			unbounded = append(unbounded, a)
		case apis.BoundedCopy[a]:
			bounded = append(bounded, a)
		}
		if apis.InputRead[a] {
			reads = append(reads, a)
		}
		if apis.FormatFamily[a] {
			hasFormat = true
		}
		if apis.ExecPrimitive[a] {
			hasExec = true
		}
	}
	hasUnbounded := len(unbounded) > 0
	hasInputRead := len(reads) > 0
	source := hasInputRead || reachable

	// Copy signal: take the strongest present, do not sum every CRT call.
	if hasUnbounded {
		score += 6
		reasons = append(reasons, "calls unbounded copy/format: "+strings.Join(unbounded, ", "))
	} else if len(bounded) > 0 {
		score += 2
		reasons = append(reasons, "calls bounded copy: "+strings.Join(bounded, ", "))
	}

	if hasInputRead {
		score += 3
		reasons = append(reasons, "reads attacker input via "+strings.Join(reads, ", "))
	}

	// The overflow shape: attacker input reaching an unbounded copy.
	if source && hasUnbounded {
		score += 5
		if hasInputRead {
			reasons = append(reasons, "reads input and performs an unbounded copy (overflow shape)")
		} else {
			reasons = append(reasons, "unbounded copy reachable from an input-reading function")
		}
	}

	// Format-string signal (OSED modules 12-13).
	if f.FormatDynamic {
		score += 4
		reasons = append(reasons, "format-family call with a non-constant format string (likely format-string bug)")
	} else if hasFormat {
		score++
	}

	if f.StringOps {
		score += 2
		reasons = append(reasons, "inline rep movs/stos copy")
	}

	// Large stack frames are where overflowable local buffers live.
	switch {
	case f.FrameSize >= 0x200:
		score += 3
		reasons = append(reasons, frameReason(f.FrameSize))
	case f.FrameSize >= 0x40:
		score++
		reasons = append(reasons, frameReason(f.FrameSize))
	}

	if hasExec {
		score++
		reasons = append(reasons, "calls a memory/exec primitive (VirtualProtect/Alloc/LoadLibrary/...)")
	}

	// Shared helpers reached from many callers are usually runtime plumbing,
	// not the specific vulnerable handler.
	if f.Callers >= 6 && !hasInputRead {
		score -= 3
		reasons = append(reasons, "high fan-in helper (down-weighted as shared utility)")
	}
	if score < 0 {
		score = 0
	}
	return score, reasons
}
