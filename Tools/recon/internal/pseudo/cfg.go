package pseudo

import "strings"

// termKind classifies how a basic block ends.
type termKind int

const (
	termFall termKind = iota // no branch; control falls into the next block
	termCond                 // conditional jump (taken -> Target, else -> next)
	termJmp                  // unconditional jump to Target
	termRet                  // return
)

// Block is a basic block: a straight run of statements with a single entry and
// a single terminating control transfer.
type Block struct {
	Idx      int
	Labels   []string // labels at the block's head (jump targets)
	Body     []Inst   // statements, excluding the terminating branch/ret
	Kind     termKind
	Target   string // termCond/termJmp: destination label ("" if indirect/external)
	CondInst Inst   // termCond: the conditional jump
	JmpInst  Inst   // termJmp: the jump (to spot tail-call thunks)
}

// cfg is the block graph plus the lookups the structurer needs.
type cfg struct {
	blocks   []Block
	labelIdx map[string]int // label -> block index
	jumpPred map[int][]int  // block index -> indices that JUMP to it (excludes fallthrough)
}

func isBranch(mnem string) bool {
	return mnem == "jmp" || (len(mnem) > 1 && mnem[0] == 'j')
}

func isTerminator(mnem string) bool {
	return isBranch(mnem) || mnem == "ret" || mnem == "retn"
}

// jumpTarget extracts a plain label operand, or "" for an indirect jump.
func jumpTarget(ops []string) string {
	if len(ops) == 0 {
		return ""
	}
	t := strings.TrimSpace(ops[0])
	t = strings.TrimPrefix(t, "short ")
	t = strings.TrimSpace(t)
	if isIdent(t) && !isReg(strings.ToLower(t)) {
		return t
	}
	return ""
}

// buildCFG splits a function's instructions into basic blocks and wires up the
// label and predecessor lookups.
func buildCFG(insts []Inst) *cfg {
	c := &cfg{labelIdx: map[string]int{}, jumpPred: map[int][]int{}}
	n := len(insts)
	i := 0
	for i < n {
		b := Block{Idx: len(c.blocks), Labels: insts[i].Labels}
		terminated := false
		j := i
		for j < n {
			in := insts[j]
			if j > i && len(in.Labels) > 0 {
				break // a labeled instruction starts the next block
			}
			if isTerminator(in.Mnem) {
				switch {
				case in.Mnem == "ret" || in.Mnem == "retn":
					b.Kind = termRet
				case in.Mnem == "jmp":
					b.Kind, b.Target, b.JmpInst = termJmp, jumpTarget(in.Ops), in
				default:
					b.Kind, b.Target, b.CondInst = termCond, jumpTarget(in.Ops), in
				}
				terminated = true
				j++
				break
			}
			b.Body = append(b.Body, in)
			j++
		}
		if !terminated {
			b.Kind = termFall
		}
		c.blocks = append(c.blocks, b)
		i = j
	}

	for _, b := range c.blocks {
		for _, lb := range b.Labels {
			c.labelIdx[lb] = b.Idx
		}
	}
	for _, b := range c.blocks {
		if (b.Kind == termCond || b.Kind == termJmp) && b.Target != "" {
			if ti, ok := c.labelIdx[b.Target]; ok {
				c.jumpPred[ti] = append(c.jumpPred[ti], b.Idx)
			}
		}
	}
	return c
}

// selfLoop reports whether block i is a single-block do/while: it ends in a
// conditional branch back to its own label, and nothing else jumps to it (so
// the head label can safely disappear into `do`).
func (c *cfg) selfLoop(i int) bool {
	b := c.blocks[i]
	if b.Kind != termCond || c.labelIdx[b.Target] != i {
		return false
	}
	preds := c.jumpPred[i]
	return len(preds) == 1 && preds[0] == i
}

// ifThenRange validates a simple if-then guarded by block i. It returns the
// index of the join block (where the then-body rejoins) and true when the
// then-body [i+1, join) is single-entry and never escapes the range.
func (c *cfg) ifThenRange(i, hi int) (join int, ok bool) {
	b := c.blocks[i]
	if b.Kind != termCond || b.Target == "" {
		return 0, false
	}
	s, exists := c.labelIdx[b.Target]
	if !exists || s <= i+1 || s > hi { // forward branch over a non-empty body
		return 0, false
	}
	// No block outside [i+1, s) may jump into it (single entry via the guard's
	// fallthrough only).
	for t := i + 1; t < s; t++ {
		for _, p := range c.jumpPred[t] {
			if p < i+1 || p >= s {
				return 0, false
			}
		}
	}
	// The body must not escape the range: every branch target stays within
	// [i+1, s] (returns are allowed).
	for t := i + 1; t < s; t++ {
		bt := c.blocks[t]
		if bt.Kind == termCond || bt.Kind == termJmp {
			if bt.Target == "" {
				return 0, false // indirect branch out of a candidate body
			}
			d, known := c.labelIdx[bt.Target]
			if !known || d < i+1 || d > s {
				return 0, false
			}
		}
	}
	return s, true
}
