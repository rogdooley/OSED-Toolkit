// Command recon is a static analysis and triage aid for Windows x86 exploit
// development (OSED). It is built as a single static executable so it can be
// dropped onto an air-gapped Win10 x86 exam machine with no Python, no pip,
// and no external dependencies.
//
// Subcommands:
//
//	recon pe <file>        Static PE analysis: mitigations, sections,
//	                       categorized imports, gadget pre-count, scoring.
//	                       (stdlib only)
//	recon triage <file>    Disassembly-driven function ranking. (planned)
//	recon cdb <dump.txt>   Rank functions from a headless-cdb text dump. (planned)
//
// Global flags come after the subcommand, e.g. `recon pe --json app.exe`.
package main

import (
	"fmt"
	"os"
)

const usage = `recon - OSED static analysis and triage aid

usage:
  recon pe [--json|--md] <file>            static PE analysis (mitigations, imports, gadgets)
  recon triage [--json|--md] [--top N] <file>   disassembly-driven function ranking
  recon cdb [--json|--md] [--top N] [dump]      rank functions from a cdb text dump (or stdin)
  recon badchars [--json|--md] [--all] <file>   predict bad chars from the input-path disassembly
  recon filter --badchars <spec> [gadgets.txt]  drop gadget lines whose address has a bad byte
  recon pseudo [--func NAME] [listing.txt]      IDA disassembly listing -> C-like pseudocode
  recon version

Output: default is aligned text; --md is Markdown (for reports/notes); --json for tooling.

Build a Win10 x86 exe:
  GOOS=windows GOARCH=386 go build -o recon.exe .
`

const version = "recon 0.1.0"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "pe":
		os.Exit(runPE(os.Args[2:]))
	case "triage":
		os.Exit(runTriage(os.Args[2:]))
	case "cdb":
		os.Exit(runCDB(os.Args[2:]))
	case "badchars":
		os.Exit(runBadchars(os.Args[2:]))
	case "filter":
		os.Exit(runFilter(os.Args[2:]))
	case "pseudo":
		os.Exit(runPseudo(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "recon: unknown subcommand %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}
