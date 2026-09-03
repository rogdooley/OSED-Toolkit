package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"osed/recon/internal/badchars"
)

func runFilter(args []string) int {
	fs := flag.NewFlagSet("filter", flag.ContinueOnError)
	spec := fs.String("badchars", "", "bad-char spec, e.g. \\x00\\x0a\\x0d or '00 0a 0d'")
	bits := fs.Int("bits", 32, "address width in bits (32 or 64)")
	annotate := fs.Bool("annotate", false, "print every line tagged [OK]/[BAD] instead of dropping")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	bad, err := badchars.ParseSpec(*spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "recon filter: %v\n", err)
		return 2
	}
	if len(bad) == 0 {
		fmt.Fprintln(os.Stderr, "usage: recon filter --badchars '\\x00\\x0a\\x0d' [file]   (or pipe on stdin)")
		return 2
	}

	in := os.Stdin
	if fs.NArg() == 1 {
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "recon filter: %v\n", err)
			return 1
		}
		defer f.Close()
		in = f
	} else if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: recon filter --badchars <spec> [file]")
		return 2
	}

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var withAddr, kept int
	for sc.Scan() {
		line := sc.Text()
		addr, ok := badchars.ExtractAddr(line)
		if !ok {
			if *annotate {
				fmt.Fprintf(out, "       %s\n", line)
			}
			continue
		}
		withAddr++
		clean, b, pos := badchars.Clean(addr, bad, *bits)
		switch {
		case *annotate && clean:
			fmt.Fprintf(out, "[OK]   %s\n", line)
			kept++
		case *annotate:
			fmt.Fprintf(out, "[BAD 0x%02X @byte%d] %s\n", b, pos, line)
		case clean:
			fmt.Fprintln(out, line)
			kept++
		}
	}
	fmt.Fprintf(os.Stderr, "recon filter: %d of %d addresses free of bad chars\n", kept, withAddr)
	return 0
}
