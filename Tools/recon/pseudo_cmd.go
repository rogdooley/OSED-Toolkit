package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"osed/recon/internal/pseudo"
)

func runPseudo(args []string) int {
	fs := flag.NewFlagSet("pseudo", flag.ContinueOnError)
	only := fs.String("func", "", "only emit the function with this name (substring match)")
	list := fs.Bool("list", false, "list the function names found, then exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	in := os.Stdin
	if fs.NArg() == 1 {
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "recon pseudo: %v\n", err)
			return 1
		}
		defer f.Close()
		in = f
	} else if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: recon pseudo [--func NAME] [listing.txt]   (or pipe an IDA listing on stdin)")
		return 2
	}

	funcs := pseudo.Parse(in)
	if len(funcs) == 0 {
		fmt.Fprintln(os.Stderr, "recon pseudo: no functions found in input")
		return 1
	}

	if *list {
		for _, f := range funcs {
			fmt.Printf("%s  (%d instructions)\n", f.Name, len(f.Insts))
		}
		return 0
	}

	emitted := 0
	for i, f := range funcs {
		if *only != "" && !strings.Contains(f.Name, *only) {
			continue
		}
		if emitted > 0 {
			fmt.Println()
		}
		pseudo.Emit(os.Stdout, f)
		emitted++
		_ = i
	}
	if emitted == 0 {
		fmt.Fprintf(os.Stderr, "recon pseudo: no function matched %q\n", *only)
		return 1
	}
	return 0
}
