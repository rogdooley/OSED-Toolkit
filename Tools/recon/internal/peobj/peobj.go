// Package peobj is a stdlib-only static PE analyzer for exploit development.
//
// It intentionally depends only on debug/pe and the standard library so the
// `recon pe` subcommand cross-compiles to a single Win10 x86 executable with
// no external modules and no cgo. It parses headers, compile-time
// mitigations (including a manual load-config walk for SafeSEH and the GS
// cookie), sections, imports, interesting strings, and a byte-scan gadget
// pre-count. Everything here is static: no debugger or runtime state.
package peobj

import (
	"debug/pe"
	"encoding/binary"
	"os"
	"sort"
	"strings"

	"osed/recon/internal/apis"
)

// Report is the full static picture of a PE file. Exported fields so the
// report package can render text and encoding/json can emit it directly.
type Report struct {
	File           FileInfo            `json:"file"`
	Mitigations    Mitigations         `json:"mitigations"`
	MemoryLayout   MemoryLayout        `json:"memory_layout"`
	Sections       []Section           `json:"sections"`
	Imports        []ImportEntry       `json:"imports"`
	Categorized    map[string][]string `json:"categorized_imports"`
	Strings        []string            `json:"interesting_strings"`
	Gadgets        GadgetCounts        `json:"gadget_counts"`
	Exploitability Exploitability      `json:"exploitability"`
}

type FileInfo struct {
	Path            string `json:"path"`
	Size            int64  `json:"size"`
	Machine         string `json:"machine"`
	MachineRaw      uint16 `json:"machine_raw"`
	Subsystem       string `json:"subsystem"`
	SubsystemRaw    uint16 `json:"subsystem_raw"`
	Timestamp       string `json:"timestamp"`
	TimestampRaw    uint32 `json:"timestamp_raw"`
	LinkerVersion   string `json:"linker_version"`
	Is64            bool   `json:"is_64bit"`
	Characteristics uint16 `json:"characteristics"`
}

type Mitigations struct {
	NXCompat       bool `json:"nx_compat"`
	DynamicBase    bool `json:"dynamic_base"`
	HighEntropyVA  bool `json:"high_entropy_va"`
	ForceIntegrity bool `json:"force_integrity"`
	NoSEH          bool `json:"no_seh"`
	GuardCF        bool `json:"guard_cf"`
	AppContainer   bool `json:"app_container"`
	TSAware        bool `json:"terminal_server_aware"`
	Relocations    bool `json:"relocations_present"`
	// Tri-state fields: nil means "could not determine".
	GSCookie *bool `json:"gs_cookie"`
	SafeSEH  *bool `json:"safeseh"`
}

type MemoryLayout struct {
	ImageBase   uint64 `json:"image_base"`
	EntryPoint  uint64 `json:"entry_point"`
	EntryRVA    uint32 `json:"entry_rva"`
	ImageSize   uint32 `json:"image_size"`
	SizeOfStack uint64 `json:"stack_reserve"`
	SizeOfHeap  uint64 `json:"heap_reserve"`
}

type Section struct {
	Name       string  `json:"name"`
	VirtAddr   uint32  `json:"virtual_address"`
	VirtSize   uint32  `json:"virtual_size"`
	RawOffset  uint32  `json:"raw_offset"`
	RawSize    uint32  `json:"raw_size"`
	Entropy    float64 `json:"entropy"`
	Readable   bool    `json:"readable"`
	Writable   bool    `json:"writable"`
	Executable bool    `json:"executable"`
}

type ImportEntry struct {
	DLL       string   `json:"dll"`
	Functions []string `json:"functions"`
}

type GadgetCounts struct {
	Ret        int `json:"ret"`
	PopRet     int `json:"pop_ret"`
	PopPopRet  int `json:"pop_pop_ret"`
	JmpEsp     int `json:"jmp_esp"`
	CallEsp    int `json:"call_esp"`
	PushEspRet int `json:"push_esp_ret"`
	PushadRet  int `json:"pushad_ret"`
	XchgEaxEsp int `json:"xchg_eax_esp_ret"`
	AddEspRet  int `json:"add_esp_ret"`
}

type Exploitability struct {
	Score        int      `json:"score"`
	ROPCandidate bool     `json:"rop_candidate"`
	Reasons      []string `json:"reasons"`
	Warnings     []string `json:"warnings"`
}

var machineTypes = map[uint16]string{
	0x014C: "x86 (I386)",
	0x0200: "IA64",
	0x8664: "x64 (AMD64)",
	0x01C0: "ARM",
	0x01C4: "ARMv7 Thumb-2",
	0xAA64: "ARM64",
}

var subsystemTypes = map[uint16]string{
	1: "Native", 2: "Windows GUI", 3: "Windows CUI (Console)",
	5: "OS/2 CUI", 7: "POSIX CUI", 9: "Windows CE GUI",
	10: "EFI Application", 14: "Xbox", 16: "Windows Boot Application",
}

var interestingPatterns = []string{
	"http://", "https://", "ftp://",
	"cmd.exe", "cmd /c", "powershell",
	"calc.exe", "notepad.exe",
	"password", "passwd", "license", "serial",
	"admin", "backdoor", ".dll", ".bat", ".ps1",
}

// Analyze opens and fully analyzes the PE file at path.
func Analyze(path string) (*Report, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	is64, dataDirs, imageBase, entryRVA, dllChars, subsystem, linker, imageSize, stackRes, heapRes := optionalFields(f)

	rep := &Report{}
	rep.File = FileInfo{
		Path:            path,
		Size:            fi.Size(),
		Machine:         lookup(machineTypes, f.FileHeader.Machine),
		MachineRaw:      f.FileHeader.Machine,
		Subsystem:       lookup(subsystemTypes, subsystem),
		SubsystemRaw:    subsystem,
		Timestamp:       formatTimestamp(f.FileHeader.TimeDateStamp),
		TimestampRaw:    f.FileHeader.TimeDateStamp,
		LinkerVersion:   linker,
		Is64:            is64,
		Characteristics: f.FileHeader.Characteristics,
	}

	rep.Sections = sections(f)
	rep.MemoryLayout = MemoryLayout{
		ImageBase:   imageBase,
		EntryPoint:  imageBase + uint64(entryRVA),
		EntryRVA:    entryRVA,
		ImageSize:   imageSize,
		SizeOfStack: stackRes,
		SizeOfHeap:  heapRes,
	}

	imports, importSet := importList(f)
	rep.Imports = imports
	rep.Categorized = categorize(importSet)
	rep.Strings = interestingStrings(raw)
	rep.Gadgets = gadgetCounts(f)

	rep.Mitigations = mitigations(f, dllChars, dataDirs, raw, importSet)
	rep.Exploitability = score(rep)

	return rep, nil
}

// optionalFields extracts the fields that differ between the 32- and 64-bit
// optional headers into a single flat set of values.
func optionalFields(f *pe.File) (is64 bool, dd []pe.DataDirectory, imageBase uint64, entryRVA uint32, dllChars uint16, subsystem uint16, linker string, imageSize uint32, stackRes, heapRes uint64) {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dd = oh.DataDirectory[:]
		return false, dd, uint64(oh.ImageBase), oh.AddressOfEntryPoint,
			oh.DllCharacteristics, oh.Subsystem,
			version(oh.MajorLinkerVersion, oh.MinorLinkerVersion),
			oh.SizeOfImage, uint64(oh.SizeOfStackReserve), uint64(oh.SizeOfHeapReserve)
	case *pe.OptionalHeader64:
		dd = oh.DataDirectory[:]
		return true, dd, oh.ImageBase, oh.AddressOfEntryPoint,
			oh.DllCharacteristics, oh.Subsystem,
			version(oh.MajorLinkerVersion, oh.MinorLinkerVersion),
			oh.SizeOfImage, oh.SizeOfStackReserve, oh.SizeOfHeapReserve
	}
	return false, nil, 0, 0, 0, 0, "?", 0, 0, 0
}

func sections(f *pe.File) []Section {
	out := make([]Section, 0, len(f.Sections))
	for _, s := range f.Sections {
		data, _ := s.Data()
		out = append(out, Section{
			Name:       s.Name,
			VirtAddr:   s.VirtualAddress,
			VirtSize:   s.VirtualSize,
			RawOffset:  s.Offset,
			RawSize:    s.Size,
			Entropy:    round2(entropy(data)),
			Readable:   s.Characteristics&0x40000000 != 0,
			Writable:   s.Characteristics&0x80000000 != 0,
			Executable: s.Characteristics&0x20000000 != 0,
		})
	}
	return out
}

func importList(f *pe.File) ([]ImportEntry, map[string]bool) {
	set := map[string]bool{}
	syms, err := f.ImportedSymbols()
	if err != nil {
		return nil, set
	}
	byDLL := map[string][]string{}
	order := []string{}
	for _, s := range syms {
		// debug/pe formats entries as "func:DLL".
		fn, dll := s, ""
		if i := strings.LastIndex(s, ":"); i >= 0 {
			fn, dll = s[:i], s[i+1:]
		}
		if _, ok := byDLL[dll]; !ok {
			order = append(order, dll)
		}
		byDLL[dll] = append(byDLL[dll], fn)
		set[fn] = true
	}
	out := make([]ImportEntry, 0, len(order))
	for _, dll := range order {
		out = append(out, ImportEntry{DLL: dll, Functions: byDLL[dll]})
	}
	return out, set
}

func categorize(set map[string]bool) map[string][]string {
	cats := map[string][]string{}
	for name := range set {
		if c := apis.Category(name); c != "" {
			cats[c] = append(cats[c], name)
		}
	}
	for _, v := range cats {
		sort.Strings(v)
	}
	return cats
}

func mitigations(f *pe.File, dc uint16, dd []pe.DataDirectory, raw []byte, imports map[string]bool) Mitigations {
	m := Mitigations{
		NXCompat:       dc&0x0100 != 0,
		DynamicBase:    dc&0x0040 != 0,
		HighEntropyVA:  dc&0x0020 != 0,
		ForceIntegrity: dc&0x0080 != 0,
		NoSEH:          dc&0x0400 != 0,
		GuardCF:        dc&0x4000 != 0,
		AppContainer:   dc&0x1000 != 0,
		TSAware:        dc&0x8000 != 0,
	}
	// Relocations: a .reloc section or a non-empty base reloc directory (index 5).
	reloc := false
	for _, s := range f.Sections {
		if s.Name == ".reloc" {
			reloc = true
		}
	}
	if len(dd) > 5 && dd[5].Size > 0 {
		reloc = true
	}
	m.Relocations = reloc

	gs := detectGS(raw, imports)
	m.GSCookie = &gs

	m.SafeSEH = detectSafeSEH(f, dc, dd, raw)
	return m
}

func detectGS(raw []byte, imports map[string]bool) bool {
	if imports["__security_check_cookie"] || imports["__security_cookie"] {
		return true
	}
	return bytesContains(raw, []byte("__security_cookie"))
}

// detectSafeSEH walks the load config directory (index 10) to read the
// SEHandlerTable / SEHandlerCount fields. Returns nil when NO_SEH is set (the
// question does not apply) or the directory is absent/unreadable.
func detectSafeSEH(f *pe.File, dc uint16, dd []pe.DataDirectory, raw []byte) *bool {
	if dc&0x0400 != 0 { // NO_SEH: SafeSEH is not meaningful
		return nil
	}
	if len(dd) <= 10 || dd[10].VirtualAddress == 0 || dd[10].Size == 0 {
		no := false
		return &no
	}
	off, ok := rvaToOffset(f, dd[10].VirtualAddress)
	if !ok {
		return nil
	}
	// 32-bit IMAGE_LOAD_CONFIG_DIRECTORY: SEHandlerTable @0x40, count @0x44.
	// The struct's own Size field is the first dword; require it to cover 0x48.
	if off+0x48 > uint32(len(raw)) {
		no := false
		return &no
	}
	structSize := binary.LittleEndian.Uint32(raw[off:])
	if structSize < 0x48 {
		no := false
		return &no
	}
	sehTable := binary.LittleEndian.Uint32(raw[off+0x40:])
	sehCount := binary.LittleEndian.Uint32(raw[off+0x44:])
	present := sehTable != 0 && sehCount > 0
	return &present
}

// rvaToOffset maps a virtual address to a raw file offset via the section table.
func rvaToOffset(f *pe.File, rva uint32) (uint32, bool) {
	for _, s := range f.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			return s.Offset + (rva - s.VirtualAddress), true
		}
		// Some linkers leave VirtualSize small; fall back to raw size.
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.Size {
			return s.Offset + (rva - s.VirtualAddress), true
		}
	}
	return 0, false
}

func gadgetCounts(f *pe.File) GadgetCounts {
	if f.FileHeader.Machine != 0x014C { // gadget byte patterns below are x86 only
		return GadgetCounts{}
	}
	var exec []byte
	for _, s := range f.Sections {
		if s.Characteristics&0x20000000 != 0 {
			if d, err := s.Data(); err == nil {
				exec = append(exec, d...)
			}
		}
	}
	if len(exec) == 0 {
		return GadgetCounts{}
	}
	g := GadgetCounts{}
	g.Ret = count(exec, []byte{0xC3})
	g.JmpEsp = count(exec, []byte{0xFF, 0xE4})
	g.CallEsp = count(exec, []byte{0xFF, 0xD4})
	g.PushEspRet = count(exec, []byte{0x54, 0xC3})
	g.PushadRet = count(exec, []byte{0x60, 0xC3})
	g.XchgEaxEsp = count(exec, []byte{0x94, 0xC3})
	for r := 0; r < 8; r++ {
		g.PopRet += count(exec, []byte{byte(0x58 + r), 0xC3})
		for r2 := 0; r2 < 8; r2++ {
			g.PopPopRet += count(exec, []byte{byte(0x58 + r), byte(0x58 + r2), 0xC3})
		}
	}
	g.AddEspRet = countAddEspRet(exec)
	return g
}

func score(r *Report) Exploitability {
	m := r.Mitigations
	var reasons, warnings []string
	s := 0

	if !m.DynamicBase {
		reasons = append(reasons, "Fixed image base (no DYNAMIC_BASE / ASLR)")
		s += 3
	} else {
		warnings = append(warnings, "DYNAMIC_BASE set (module relocates under ASLR)")
	}
	if !m.NXCompat {
		reasons = append(reasons, "NX_COMPAT absent (DEP not requested)")
		s += 2
	} else {
		warnings = append(warnings, "NX_COMPAT set (DEP)")
	}
	if !m.Relocations {
		reasons = append(reasons, "No relocations present")
		s += 2
	}
	if m.SafeSEH != nil && !*m.SafeSEH {
		reasons = append(reasons, "No SafeSEH")
		s += 2
	} else if m.SafeSEH != nil && *m.SafeSEH {
		warnings = append(warnings, "SafeSEH table present")
	}
	if m.GSCookie != nil && !*m.GSCookie {
		reasons = append(reasons, "No GS security cookie")
		s++
	} else if m.GSCookie != nil && *m.GSCookie {
		warnings = append(warnings, "GS security cookie detected")
	}
	if !m.GuardCF {
		reasons = append(reasons, "No CFG")
		s++
	} else {
		warnings = append(warnings, "CFG enabled")
	}
	if r.Gadgets.Ret > 50 {
		reasons = append(reasons, itoaReason(r.Gadgets.Ret, "RET gadgets"))
		s++
	}
	if r.Gadgets.JmpEsp > 0 {
		reasons = append(reasons, itoaReason(r.Gadgets.JmpEsp, "JMP ESP gadgets"))
		s += 2
	}
	if r.Categorized[apis.CatExploitation] != nil {
		for _, api := range r.Categorized[apis.CatExploitation] {
			if api == "VirtualProtect" || api == "VirtualAlloc" {
				reasons = append(reasons, "Imports "+api)
				s++
				break
			}
		}
	}
	return Exploitability{Score: s, ROPCandidate: s >= 6, Reasons: reasons, Warnings: warnings}
}
