package main

import (
	"flag"
	"fmt"
	"os"

	"osed/recon/internal/badchars"
	"osed/recon/internal/disasm"
	"osed/recon/internal/img"
	"osed/recon/internal/report"
)

func runBadchars(args []string) int {
	fs := flag.NewFlagSet("badchars", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON")
	asMD := fs.Bool("md", false, "emit Markdown")
	all := fs.Bool("all", false, "scan every function, not just the input path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: recon badchars [--json|--md] [--all] <file>")
		return 2
	}
	im, err := img.Load(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "recon badchars: %v\n", err)
		return 1
	}
	cands, scoped := badchars.Predict(disasm.Sweep(im), *all)
	switch {
	case *asJSON:
		if err := report.BadcharsJSON(os.Stdout, cands, scoped); err != nil {
			fmt.Fprintf(os.Stderr, "recon badchars: %v\n", err)
			return 1
		}
	case *asMD:
		report.BadcharsMarkdown(os.Stdout, cands, scoped)
	default:
		report.BadcharsText(os.Stdout, cands, scoped)
	}
	return 0
}
