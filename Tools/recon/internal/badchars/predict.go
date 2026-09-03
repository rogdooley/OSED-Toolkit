package badchars

import (
	"fmt"
	"sort"

	"osed/recon/internal/analysis"
	"osed/recon/internal/apis"
)

// Confidence buckets a predicted bad char by how likely it really is one.
type Confidence int

const (
	// High: a null terminator implied by a null-terminating string copy.
	High Confidence = iota
	// Likely: a control/whitespace byte the input path compares against
	// (classic delimiter/terminator: 0x00-0x20).
	Likely
	// Possible: a punctuation byte compared in the input path.
	Possible
	// Keyword: an alphanumeric byte compared - usually protocol/command
	// dispatch (e.g. 'T' of TRUN), NOT a bad char. Reported for context.
	Keyword
)

func (c Confidence) String() string {
	switch c {
	case High:
		return "high"
	case Likely:
		return "likely"
	case Possible:
		return "possible"
	default:
		return "keyword"
	}
}

// Candidate is a predicted bad char with its evidence.
type Candidate struct {
	Byte       byte       `json:"byte"`
	Confidence string     `json:"confidence"`
	confRank   Confidence // for sorting, not serialized
	Sites      int        `json:"sites"`
	Reasons    []string   `json:"reasons"`
}

// Predict statically predicts candidate bad chars from disassembled functions.
// It scopes to functions reachable from an input source (the data path) unless
// all is set, aggregates their 8-bit constant compares, and infers 0x00 from
// null-terminating string copies. It never asserts: results must be confirmed
// dynamically by sending a full 0x01..0xff byte array and comparing in a
// debugger. The second result reports how many functions were in scope.
func Predict(funcs []analysis.Func, all bool) ([]Candidate, int) {
	reach := analysis.InputReachable(funcs)
	agg := map[byte]*Candidate{}
	add := func(b byte, conf Confidence, reason string) {
		c := agg[b]
		if c == nil {
			c = &Candidate{Byte: b, confRank: conf}
			agg[b] = c
		}
		if conf < c.confRank {
			c.confRank = conf // keep the strongest confidence seen
		}
		c.Sites++
		if len(c.Reasons) < 6 {
			for _, r := range c.Reasons {
				if r == reason {
					return
				}
			}
			c.Reasons = append(c.Reasons, reason)
		}
	}

	scoped := 0
	for i := range funcs {
		f := &funcs[i]
		if f.ThunkAPI != "" {
			continue
		}
		if !all && !reach[f.Start] {
			continue
		}
		scoped++

		for _, c := range f.Calls {
			if apis.UnboundedCopy[c.API] {
				add(0x00, High, fmt.Sprintf("null-terminated copy %s in %s", c.API, f.Name))
			}
		}
		for _, bc := range f.ByteCmps {
			add(bc.Imm, classify(bc.Imm), fmt.Sprintf("compared in %s @0x%X", f.Name, bc.Site))
		}
	}

	out := make([]Candidate, 0, len(agg))
	for _, c := range agg {
		c.Confidence = c.confRank.String()
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].confRank != out[j].confRank {
			return out[i].confRank < out[j].confRank
		}
		if out[i].Sites != out[j].Sites {
			return out[i].Sites > out[j].Sites
		}
		return out[i].Byte < out[j].Byte
	})
	return out, scoped
}

// classify buckets a compared byte by how likely it is an actual bad char.
func classify(b byte) Confidence {
	switch {
	case b <= 0x20: // control chars and space: classic delimiters/terminators
		return Likely
	case (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z'):
		return Keyword
	default:
		return Possible
	}
}
