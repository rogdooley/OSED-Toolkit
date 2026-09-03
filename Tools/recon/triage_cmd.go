package main

import (
	"flag"
	"fmt"
	"os"

	"osed/recon/internal/analysis"
	"osed/recon/internal/disasm"
	"osed/recon/internal/img"
	"osed/recon/internal/report"
)

func runTriage(args []string) int {
	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	asMD := fs.Bool("md", false, "emit Markdown")
	top := fs.Int("top", 40, "max ranked functions to print (0 = all)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: recon triage [--json|--md] [--top N] <file>")
		return 2
	}
	im, err := img.Load(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "recon triage: %v\n", err)
		return 1
	}
	ranked := analysis.Rank(disasm.Sweep(im))
	switch {
	case *asJSON:
		if err := report.TriageJSON(os.Stdout, ranked); err != nil {
			fmt.Fprintf(os.Stderr, "recon triage: %v\n", err)
			return 1
		}
	case *asMD:
		report.TriageMarkdown(os.Stdout, ranked, *top)
	default:
		report.TriageText(os.Stdout, ranked, *top)
	}
	return 0
}
