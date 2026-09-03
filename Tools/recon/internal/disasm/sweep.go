// Package disasm performs a bounded recursive-descent sweep of a loaded PE
// image and produces the analysis.Func model. It follows direct calls (each
// becomes a new function seed) and intra-function branches, resolving calls to
// imports through the IAT and through single-instruction `jmp [IAT]` thunks.
//
// This is deliberately a triage-grade sweep, not a perfect recovery: it favors
// breadth and never crashes on bad bytes. Indirect calls/jumps end a path.
package disasm

import (
	"osed/recon/internal/analysis"
	"osed/recon/internal/apis"
	"osed/recon/internal/img"

	"golang.org/x/arch/x86/x86asm"
)

const (
	maxInstrPerFunc = 20000
	maxFuncs        = 200000
)

// Sweep disassembles the image starting from its seeds and returns the
// discovered functions (unranked; call analysis.Rank on the result).
func Sweep(im *img.Image) []analysis.Func {
	funcs := map[uint64]*analysis.Func{}
	queue := append([]uint64{}, im.Seeds()...)

	for len(queue) > 0 && len(funcs) < maxFuncs {
		start := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if _, done := funcs[start]; done {
			continue
		}
		if !im.Exec(start) {
			continue
		}
		fn := &analysis.Func{Start: start, Name: funcName(im, start)}
		funcs[start] = fn
		analyzeFunc(im, fn, &queue)
	}

	// Resolve internal calls that land on a `jmp [IAT]` thunk to their API,
	// and tally how many functions call each target.
	for _, fn := range funcs {
		for i := range fn.Calls {
			c := &fn.Calls[i]
			if c.API == "" && c.Target != 0 {
				if callee, ok := funcs[c.Target]; ok && callee.ThunkAPI != "" {
					c.API = callee.ThunkAPI
				}
			}
			if c.Target != 0 {
				if callee, ok := funcs[c.Target]; ok {
					callee.Callers++
				}
			}
		}
	}

	out := make([]analysis.Func, 0, len(funcs))
	for _, fn := range funcs {
		out = append(out, *fn)
	}
	return out
}

// analyzeFunc does a BFS over the basic blocks reachable within one function,
// recording call sites, frame size and string-copy signals. It appends newly
// discovered callee starts to the shared queue.
func analyzeFunc(im *img.Image, fn *analysis.Func, queue *[]uint64) {
	visited := map[uint64]bool{}
	blocks := []uint64{fn.Start}
	count := 0
	strSeen := map[string]bool{}
	lastStrPushAt := -1 // instruction index of the last push of a string pointer

	// Thunk detection: a function whose very first instruction is `jmp [IAT]`.
	if raw, ok := im.ReadAt(fn.Start); ok {
		if inst, err := x86asm.Decode(raw, im.Bits); err == nil && inst.Op == x86asm.JMP {
			if abs, isMem := memAbs(inst, im.Bits); isMem {
				if api, ok := im.APIAt(abs); ok {
					fn.ThunkAPI = api
				}
			}
		}
	}

	for len(blocks) > 0 {
		va := blocks[len(blocks)-1]
		blocks = blocks[:len(blocks)-1]

		for {
			if count > maxInstrPerFunc || visited[va] || !im.Exec(va) {
				break
			}
			raw, ok := im.ReadAt(va)
			if !ok || len(raw) == 0 {
				break
			}
			inst, err := x86asm.Decode(raw, im.Bits)
			if err != nil || inst.Len == 0 {
				break
			}
			visited[va] = true
			count++
			next := va + uint64(inst.Len)

			// Record 8-bit compares against constants: candidate bad chars in
			// an input-handling function (delimiter/terminator byte checks).
			if imm, ok := byteCmpImm(inst); ok && len(fn.ByteCmps) < 64 {
				fn.ByteCmps = append(fn.ByteCmps, analysis.ByteCmp{Imm: imm, Site: va})
			}

			// Resolve any string-pointer operands (push offset str, lea, mov imm).
			if refs, isStr := stringRefs(im, inst); len(refs) > 0 {
				for _, s := range refs {
					if !strSeen[s] && len(fn.Strings) < 16 {
						strSeen[s] = true
						fn.Strings = append(fn.Strings, s)
					}
				}
				if inst.Op == x86asm.PUSH && isStr {
					lastStrPushAt = count
				}
			}

			switch inst.Op {
			case x86asm.RET, x86asm.LRET, x86asm.IRET, x86asm.HLT, x86asm.UD2:
				va = 0
			case x86asm.CALL:
				recentStr := lastStrPushAt >= 0 && count-lastStrPushAt <= 5
				recordCall(im, fn, va, inst, queue, recentStr)
				va = next
				continue
			case x86asm.JMP:
				if t, ok := relTarget(inst, va); ok {
					if isFunctionStart(im, fn, t) {
						// tail call to another function
						fn.Calls = append(fn.Calls, analysis.Call{Site: va, Target: t, API: apiFor(im, t)})
						enqueue(queue, t)
					} else {
						blocks = append(blocks, t)
					}
				}
				va = 0
			case x86asm.SUB:
				if fs, ok := espFrame(inst, im.Bits); ok && fs > fn.FrameSize {
					fn.FrameSize = fs
				}
				va = next
				continue
			case x86asm.MOVSB, x86asm.MOVSW, x86asm.MOVSD, x86asm.STOSB, x86asm.STOSW, x86asm.STOSD:
				fn.StringOps = true
				va = next
				continue
			default:
				// Conditional/loop branch: has a PC-relative target but is not
				// call/jmp/ret. Queue the branch target, fall through.
				if t, ok := relTarget(inst, va); ok {
					blocks = append(blocks, t)
				}
				va = next
				continue
			}
			if va == 0 {
				break
			}
		}
	}
}

func recordCall(im *img.Image, fn *analysis.Func, site uint64, inst x86asm.Inst, queue *[]uint64, recentStrPush bool) {
	var api string
	if t, ok := relTarget(inst, site); ok {
		api = apiFor(im, t)
		fn.Calls = append(fn.Calls, analysis.Call{Site: site, Target: t, API: api})
		enqueue(queue, t)
	} else if abs, ok := memAbs(inst, im.Bits); ok {
		if a, ok := im.APIAt(abs); ok {
			api = a
			fn.Calls = append(fn.Calls, analysis.Call{Site: site, API: api})
		}
	}
	// Format-string heuristic: a printf-family call with no constant string
	// pushed just before it means the format argument is attacker-influenced.
	if api != "" && apis.FormatFamily[api] && !recentStrPush {
		fn.FormatDynamic = true
	}
}

func apiFor(im *img.Image, target uint64) string {
	if api, ok := im.APIAt(target); ok {
		return api
	}
	return ""
}

// isFunctionStart reports whether a jump target looks like a separate function
// rather than a block inside the current one (backward jump, or a jump to a
// known symbol that is not the current function's start).
func isFunctionStart(im *img.Image, fn *analysis.Func, target uint64) bool {
	if target == fn.Start {
		return false
	}
	if _, ok := im.SymAt(target); ok {
		return true
	}
	return target < fn.Start
}

func funcName(im *img.Image, va uint64) string {
	if n, ok := im.SymAt(va); ok {
		return n
	}
	return "sub_" + hex(va)
}

func enqueue(queue *[]uint64, va uint64) { *queue = append(*queue, va) }
