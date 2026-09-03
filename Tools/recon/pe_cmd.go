package main

import (
	"flag"
	"fmt"
	"os"

	"osed/recon/internal/peobj"
	"osed/recon/internal/report"
)

func runPE(args []string) int {
	fs := flag.NewFlagSet("pe", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit JSON instead of text")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: recon pe [--json] <file>")
		return 2
	}
	rep, err := peobj.Analyze(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "recon pe: %v\n", err)
		return 1
	}
	if *asJSON {
		if err := report.PEJSON(os.Stdout, rep); err != nil {
			fmt.Fprintf(os.Stderr, "recon pe: %v\n", err)
			return 1
		}
		return 0
	}
	report.PEText(os.Stdout, rep)
	return 0
}
