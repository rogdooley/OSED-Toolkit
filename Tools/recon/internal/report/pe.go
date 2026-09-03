// Package report renders analysis results as plain text or JSON. Plain text
// only, no color escapes, so output stays readable when piped through WinDbg
// scratch files or copied out of a locked-down exam console.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"osed/recon/internal/peobj"
)

// PEJSON writes the report as indented JSON.
func PEJSON(w io.Writer, r *peobj.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// PEText writes a human-readable report.
func PEText(w io.Writer, r *peobj.Report) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	line := strings.Repeat("=", 60)

	p("%s", line)
	p("FILE")
	p("%s", line)
	p("  Path        : %s", r.File.Path)
	p("  Size        : %d bytes", r.File.Size)
	p("  Machine     : %s", r.File.Machine)
	p("  Subsystem   : %s", r.File.Subsystem)
	p("  Linker      : %s", r.File.LinkerVersion)
	p("  Timestamp   : %s", r.File.Timestamp)
	p("  64-bit      : %v", r.File.Is64)

	p("\n%s\nMITIGATIONS\n%s", line, line)
	m := r.Mitigations
	p("  ASLR (DYNAMIC_BASE) : %s", yn(m.DynamicBase))
	p("  High-entropy VA     : %s", yn(m.HighEntropyVA))
	p("  DEP (NX_COMPAT)     : %s", yn(m.NXCompat))
	p("  SafeSEH             : %s", tri(m.SafeSEH))
	p("  NO_SEH              : %s", yn(m.NoSEH))
	p("  GS cookie           : %s", tri(m.GSCookie))
	p("  CFG (GUARD_CF)      : %s", yn(m.GuardCF))
	p("  Relocations present : %s", yn(m.Relocations))
	p("  Force integrity     : %s", yn(m.ForceIntegrity))

	p("\n%s\nMEMORY LAYOUT\n%s", line, line)
	l := r.MemoryLayout
	p("  Image base   : 0x%08X", l.ImageBase)
	p("  Entry point  : 0x%08X (RVA 0x%X)", l.EntryPoint, l.EntryRVA)
	p("  Image size   : 0x%X", l.ImageSize)
	p("  Stack reserve: 0x%X", l.SizeOfStack)

	p("\n%s\nSECTIONS\n%s", line, line)
	p("  %-10s %-10s %-10s %-8s %s", "NAME", "VADDR", "VSIZE", "ENTROPY", "PERMS")
	for _, s := range r.Sections {
		perms := permStr(s.Readable, s.Writable, s.Executable)
		flag := ""
		if s.Writable && s.Executable {
			flag = "  <- W+X"
		}
		p("  %-10s 0x%08X 0x%-8X %-8.2f %s%s", s.Name, s.VirtAddr, s.VirtSize, s.Entropy, perms, flag)
	}

	p("\n%s\nCATEGORIZED IMPORTS\n%s", line, line)
	if len(r.Categorized) == 0 {
		p("  (none matched)")
	}
	for _, cat := range []string{"exploitation", "dangerous_crt", "networking", "file_io", "process", "registry", "crypto"} {
		if names := r.Categorized[cat]; len(names) > 0 {
			p("  %-14s: %s", cat, strings.Join(names, ", "))
		}
	}

	p("\n%s\nGADGET PRE-COUNT (x86 byte scan)\n%s", line, line)
	g := r.Gadgets
	p("  ret=%d  pop;ret=%d  pop;pop;ret=%d", g.Ret, g.PopRet, g.PopPopRet)
	p("  jmp esp=%d  call esp=%d  push esp;ret=%d", g.JmpEsp, g.CallEsp, g.PushEspRet)
	p("  pushad;ret=%d  xchg eax,esp;ret=%d  add esp,x;ret=%d", g.PushadRet, g.XchgEaxEsp, g.AddEspRet)

	if len(r.Strings) > 0 {
		p("\n%s\nINTERESTING STRINGS (first %d)\n%s", line, len(r.Strings), line)
		for _, s := range r.Strings {
			p("  %s", s)
		}
	}

	p("\n%s\nEXPLOITABILITY\n%s", line, line)
	e := r.Exploitability
	p("  Score        : %d", e.Score)
	p("  ROP candidate: %s", yn(e.ROPCandidate))
	if len(e.Reasons) > 0 {
		p("  Favorable:")
		for _, x := range e.Reasons {
			p("    + %s", x)
		}
	}
	if len(e.Warnings) > 0 {
		p("  Obstacles:")
		for _, x := range e.Warnings {
			p("    - %s", x)
		}
	}
}

// PEMarkdown writes the report as GitHub-flavored Markdown, for pasting into
// notes or an exam report.
func PEMarkdown(w io.Writer, r *peobj.Report) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }

	p("# PE Report: %s\n", filepath.Base(r.File.Path))
	p("`%s`\n", r.File.Path)

	p("## File\n")
	p("| Field | Value |")
	p("| --- | --- |")
	p("| Machine | %s |", r.File.Machine)
	p("| Subsystem | %s |", r.File.Subsystem)
	p("| Linker | %s |", r.File.LinkerVersion)
	p("| Timestamp | %s |", r.File.Timestamp)
	p("| Size | %d bytes |", r.File.Size)
	p("| 64-bit | %v |", r.File.Is64)

	p("\n## Mitigations\n")
	p("| Mitigation | State |")
	p("| --- | --- |")
	m := r.Mitigations
	p("| ASLR (DYNAMIC_BASE) | %s |", yn(m.DynamicBase))
	p("| DEP (NX_COMPAT) | %s |", yn(m.NXCompat))
	p("| SafeSEH | %s |", tri(m.SafeSEH))
	p("| NO_SEH | %s |", yn(m.NoSEH))
	p("| GS cookie | %s |", tri(m.GSCookie))
	p("| CFG (GUARD_CF) | %s |", yn(m.GuardCF))
	p("| Relocations | %s |", yn(m.Relocations))

	l := r.MemoryLayout
	p("\n## Memory layout\n")
	p("- Image base: `0x%08X`", l.ImageBase)
	p("- Entry point: `0x%08X` (RVA `0x%X`)", l.EntryPoint, l.EntryRVA)
	p("- Image size: `0x%X`", l.ImageSize)

	p("\n## Sections\n")
	p("| Name | VAddr | VSize | Entropy | Perms |")
	p("| --- | --- | --- | --- | --- |")
	for _, s := range r.Sections {
		perms := permStr(s.Readable, s.Writable, s.Executable)
		if s.Writable && s.Executable {
			perms += " (W+X)"
		}
		p("| %s | `0x%08X` | `0x%X` | %.2f | %s |", s.Name, s.VirtAddr, s.VirtSize, s.Entropy, perms)
	}

	p("\n## Categorized imports\n")
	if len(r.Categorized) == 0 {
		p("_none matched_")
	}
	for _, cat := range []string{"exploitation", "dangerous_crt", "networking", "file_io", "process", "registry", "crypto"} {
		if names := r.Categorized[cat]; len(names) > 0 {
			p("- **%s**: %s", cat, strings.Join(names, ", "))
		}
	}

	g := r.Gadgets
	p("\n## Gadget pre-count (x86 byte scan)\n")
	p("| Gadget | Count |")
	p("| --- | --- |")
	for _, kv := range []struct {
		k string
		v int
	}{
		{"ret", g.Ret}, {"pop; ret", g.PopRet}, {"pop; pop; ret", g.PopPopRet},
		{"jmp esp", g.JmpEsp}, {"call esp", g.CallEsp}, {"push esp; ret", g.PushEspRet},
		{"pushad; ret", g.PushadRet}, {"xchg eax,esp; ret", g.XchgEaxEsp}, {"add esp,x; ret", g.AddEspRet},
	} {
		p("| %s | %d |", kv.k, kv.v)
	}

	if len(r.Strings) > 0 {
		p("\n## Interesting strings\n")
		for _, s := range r.Strings {
			p("- `%s`", s)
		}
	}

	e := r.Exploitability
	p("\n## Exploitability\n")
	p("**Score %d - ROP candidate: %s**\n", e.Score, yn(e.ROPCandidate))
	if len(e.Reasons) > 0 {
		p("Favorable:")
		for _, x := range e.Reasons {
			p("- %s", x)
		}
	}
	if len(e.Warnings) > 0 {
		p("\nObstacles:")
		for _, x := range e.Warnings {
			p("- %s", x)
		}
	}
}

func yn(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func tri(b *bool) string {
	if b == nil {
		return "Unknown"
	}
	return yn(*b)
}

func permStr(r, w, x bool) string {
	s := ""
	for _, p := range []struct {
		ok bool
		c  string
	}{{r, "R"}, {w, "W"}, {x, "X"}} {
		if p.ok {
			s += p.c
		} else {
			s += "-"
		}
	}
	return s
}
