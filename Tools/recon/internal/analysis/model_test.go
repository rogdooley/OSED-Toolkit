package analysis

import "testing"

func TestRankPrioritizesSourceAndSink(t *testing.T) {
	funcs := []Func{
		{Start: 0x1000, Name: "handler", Calls: []Call{
			{API: "recv"}, {API: "strcpy"},
		}, FrameSize: 0x400},
		{Start: 0x2000, Name: "logger", Calls: []Call{{API: "fprintf"}}},
		{Start: 0x3000, Name: "thunk", ThunkAPI: "strcpy"},
	}
	got := Rank(funcs)

	if len(got) != 2 {
		t.Fatalf("thunk should be dropped: got %d funcs", len(got))
	}
	if got[0].Name != "handler" {
		t.Fatalf("top func = %q, want handler", got[0].Name)
	}
	// recv(4) + strcpy(5) + source/sink synergy(4) + frame>=0x200(3) = 16
	if got[0].Score < got[1].Score {
		t.Fatalf("handler (%d) should outrank logger (%d)", got[0].Score, got[1].Score)
	}
	if got[0].Score != 16 {
		t.Fatalf("handler score = %d, want 16", got[0].Score)
	}
}

func TestRankFlagsDynamicFormatString(t *testing.T) {
	funcs := []Func{
		{Start: 0x1000, Name: "vuln_log", Calls: []Call{{API: "printf"}}, FormatDynamic: true},
		{Start: 0x2000, Name: "safe_log", Calls: []Call{{API: "printf"}}},
	}
	got := Rank(funcs)

	vuln := got[0]
	if vuln.Name != "vuln_log" {
		t.Fatalf("top = %q, want vuln_log", vuln.Name)
	}
	// printf: dangerous(5) + format-family(2) + non-constant format(4) = 11
	if vuln.Score != 11 {
		t.Fatalf("vuln_log score = %d, want 11", vuln.Score)
	}
	if got[1].Score != 7 { // printf without the dynamic-format bonus
		t.Fatalf("safe_log score = %d, want 7", got[1].Score)
	}
}
