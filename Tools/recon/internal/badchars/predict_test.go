package badchars

import (
	"testing"

	"osed/recon/internal/analysis"
)

func TestPredictBucketsAndScope(t *testing.T) {
	funcs := []analysis.Func{
		{
			Start: 0x1000, Name: "handler",
			Calls: []analysis.Call{{API: "recv"}, {API: "strcpy"}},
			ByteCmps: []analysis.ByteCmp{
				{Imm: 0x0a, Site: 0x1010}, {Imm: 0x0d, Site: 0x1014},
				{Imm: 0x54, Site: 0x1020}, // 'T' - command dispatch, not a bad char
			},
		},
		// Not on the input path and no --all: must be ignored.
		{Start: 0x2000, Name: "unrelated", ByteCmps: []analysis.ByteCmp{{Imm: 0x99}}},
	}

	cands, scoped := Predict(funcs, false)
	if scoped != 1 {
		t.Fatalf("scoped = %d, want 1 (only the recv handler)", scoped)
	}
	got := map[byte]string{}
	for _, c := range cands {
		got[c.Byte] = c.Confidence
	}
	if got[0x00] != "high" {
		t.Errorf("0x00 = %q, want high (null-terminated strcpy)", got[0x00])
	}
	if got[0x0a] != "likely" || got[0x0d] != "likely" {
		t.Errorf("0x0a/0x0d = %q/%q, want likely", got[0x0a], got[0x0d])
	}
	if got[0x54] != "keyword" {
		t.Errorf("0x54 ('T') = %q, want keyword (protocol dispatch)", got[0x54])
	}
	if _, seen := got[0x99]; seen {
		t.Error("0x99 from an off-path function must not appear without --all")
	}
}

func TestPredictAllScope(t *testing.T) {
	funcs := []analysis.Func{
		{Start: 0x2000, Name: "parser", ByteCmps: []analysis.ByteCmp{{Imm: 0x2f}}}, // '/'
	}
	cands, scoped := Predict(funcs, true)
	if scoped != 1 || len(cands) != 1 || cands[0].Byte != 0x2f {
		t.Fatalf("--all should scan the function: scoped=%d cands=%v", scoped, cands)
	}
	if cands[0].Confidence != "possible" {
		t.Errorf("0x2f = %q, want possible", cands[0].Confidence)
	}
}
