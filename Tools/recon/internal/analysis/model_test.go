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
	// strcpy unbounded(6) + recv read(3) + overflow synergy(5) + frame>=0x200(3) = 17
	if got[0].Score != 17 {
		t.Fatalf("handler score = %d, want 17", got[0].Score)
	}
	// fprintf is a format sink only: +1
	if got[1].Score != 1 {
		t.Fatalf("logger score = %d, want 1", got[1].Score)
	}
}

// A recv in one function and the unbounded strcpy in a callee: the callee must
// still score the overflow synergy via call-graph reachability, and outrank the
// reader on the strength of the unbounded copy + large frame.
func TestRankPropagatesInputReachability(t *testing.T) {
	funcs := []Func{
		{Start: 0x1000, Name: "ConnectionHandler", Calls: []Call{
			{API: "recv"}, {Target: 0x2000}, // dispatches to the sink
		}},
		{Start: 0x2000, Name: "TrunHandler", Calls: []Call{
			{API: "strcpy"},
		}, FrameSize: 0x7E8, Callers: 1},
	}
	got := Rank(funcs)

	sink := findByName(got, "TrunHandler")
	if sink == nil {
		t.Fatal("TrunHandler missing")
	}
	// unbounded(6) + reachable synergy(5) + frame>=0x200(3) = 14
	if sink.Score != 14 {
		t.Fatalf("TrunHandler score = %d, want 14", sink.Score)
	}
	if got[0].Name != "TrunHandler" {
		t.Fatalf("top = %q, want TrunHandler (should outrank the recv handler)", got[0].Name)
	}
}

// A high-fan-in helper that does not read input is down-weighted, so a genuine
// low-fan-in unbounded-copy handler outranks runtime plumbing.
func TestRankDownweightsSharedHelpers(t *testing.T) {
	funcs := []Func{
		{Start: 0x1000, Name: "__write_memory", Calls: []Call{
			{API: "VirtualProtect"}, {API: "memcpy"},
		}, FrameSize: 0x48, Callers: 12},
		{Start: 0x2000, Name: "Function3", Calls: []Call{{API: "strcpy"}}, FrameSize: 0x408, Callers: 1},
	}
	got := Rank(funcs)
	if got[0].Name != "Function3" {
		t.Fatalf("top = %q, want Function3", got[0].Name)
	}
	helper := findByName(got, "__write_memory")
	// bounded(2) + frame>=0x40(1) + exec(1) - fan-in(3) = 1
	if helper.Score != 1 {
		t.Fatalf("__write_memory score = %d, want 1", helper.Score)
	}
}

func TestRankFlagsDynamicFormatString(t *testing.T) {
	funcs := []Func{
		{Start: 0x1000, Name: "vuln_log", Calls: []Call{{API: "printf"}}, FormatDynamic: true},
		{Start: 0x2000, Name: "safe_log", Calls: []Call{{API: "printf"}}},
	}
	got := Rank(funcs)

	if got[0].Name != "vuln_log" {
		t.Fatalf("top = %q, want vuln_log", got[0].Name)
	}
	if got[0].Score != 4 { // non-constant format bonus
		t.Fatalf("vuln_log score = %d, want 4", got[0].Score)
	}
	if got[1].Score != 1 { // plain format sink
		t.Fatalf("safe_log score = %d, want 1", got[1].Score)
	}
}

func findByName(fs []Func, name string) *Func {
	for i := range fs {
		if fs[i].Name == name {
			return &fs[i]
		}
	}
	return nil
}
