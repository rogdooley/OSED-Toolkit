package main

import (
	"flag"
	"fmt"
	"os"

	"osed/recon/internal/analysis"
	"osed/recon/internal/cdb"
	"osed/recon/internal/report"
)

func runCDB(args []string) int {
	fs := flag.NewFlagSet("cdb", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON instead of text")
	top := fs.Int("top", 40, "max ranked functions to print (0 = all)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	in := os.Stdin
	if fs.NArg() == 1 {
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "recon cdb: %v\n", err)
			return 1
		}
		defer f.Close()
		in = f
	} else if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: recon cdb [--json] [--top N] [dump.txt]   (or pipe on stdin)")
		return 2
	}

	ranked := analysis.Rank(cdb.Parse(in))
	if *asJSON {
		if err := report.TriageJSON(os.Stdout, ranked); err != nil {
			fmt.Fprintf(os.Stderr, "recon cdb: %v\n", err)
			return 1
		}
		return 0
	}
	report.TriageText(os.Stdout, ranked, *top)
	return 0
}
