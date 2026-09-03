// Package analysis holds the frontend-independent function model and the
// ranking logic. Both the disasm frontend (static, x86asm) and the cdb
// frontend (text dump from a headless debugger) produce []Func and hand it to
// Rank, so the two paths always agree on how targets are scored.
package analysis

import (
	"sort"

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
	Start     uint64   `json:"start"`
	Name      string   `json:"name"`
	FrameSize int64    `json:"frame_size"` // bytes from `sub esp, imm` prologue
	Calls     []Call   `json:"calls"`
	StringOps bool     `json:"string_ops"` // rep movs / rep stos present
	ThunkAPI  string   `json:"thunk_api"`  // set if the function is just `jmp [IAT]`
	Score     int      `json:"score"`
	Reasons   []string `json:"reasons"`
}

// apiCalls returns the distinct resolved API names called by the function.
func (f *Func) apiCalls() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range f.Calls {
		if c.API != "" && !seen[c.API] {
			seen[c.API] = true
			out = append(out, c.API)
		}
	}
	return out
}

// Rank scores every function in place and returns them sorted most-interesting
// first. Thunk functions (bare `jmp [IAT]`) are dropped from the ranked view;
// they carry no logic of their own.
func Rank(funcs []Func) []Func {
	var out []Func
	for i := range funcs {
		f := funcs[i]
		if f.ThunkAPI != "" {
			continue
		}
		f.Score, f.Reasons = scoreFunc(&f)
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

func scoreFunc(f *Func) (int, []string) {
	score := 0
	var reasons []string

	called := f.apiCalls()
	hasSink := false
	hasSource := false
	hasFormat := false
	for _, api := range called {
		if w := apis.SinkWeight(api); w > 0 {
			score += w
			if apis.DangerousCRT[api] {
				hasSink = true
				reasons = append(reasons, "calls dangerous copy/format "+api)
			} else if apis.Networking[api] {
				hasSource = true
				reasons = append(reasons, "reads input via "+api)
			} else {
				reasons = append(reasons, "calls "+api)
			}
		}
		if apis.FormatFamily[api] {
			hasFormat = true
		}
	}

	// Synergy: an input source and a dangerous sink in the same function is
	// the classic remote-overflow shape.
	if hasSource && hasSink {
		score += 4
		reasons = append(reasons, "input source and copy sink in same function")
	}
	if hasFormat {
		score += 2
		reasons = append(reasons, "format-string family call (check for non-literal format)")
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
		score += 1
		reasons = append(reasons, frameReason(f.FrameSize))
	}
	return score, reasons
}
