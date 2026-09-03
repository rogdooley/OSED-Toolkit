// Package img loads a PE file into a virtual-address-addressable image for
// disassembly. It provides byte access at any VA, the IAT map (VA of an import
// thunk slot -> API name) needed to resolve `call [IAT]`, and a set of
// function-start seeds (entry point plus any COFF symbols).
//
// Stdlib only apart from what the caller layers on top; the x86 disassembler
// lives in the disasm package.
package img

import (
	"debug/pe"
	"encoding/binary"
)

type segment struct {
	va   uint64
	data []byte
	exec bool
}

// Image is a loaded PE ready for disassembly.
type Image struct {
	Bits      int // 32 or 64
	ImageBase uint64
	Entry     uint64 // absolute VA of entry point
	segs      []segment
	iat       map[uint64]string // VA of IAT slot -> imported name
	syms      map[uint64]string // VA -> symbol name
	seeds     []uint64          // candidate function starts
}

// Load parses the PE at path into an Image.
func Load(path string) (*Image, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	im := &Image{iat: map[uint64]string{}, syms: map[uint64]string{}}

	var dataDirs []pe.DataDirectory
	var entryRVA uint32
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		im.Bits = 32
		im.ImageBase = uint64(oh.ImageBase)
		entryRVA = oh.AddressOfEntryPoint
		dataDirs = oh.DataDirectory[:]
	case *pe.OptionalHeader64:
		im.Bits = 64
		im.ImageBase = oh.ImageBase
		entryRVA = oh.AddressOfEntryPoint
		dataDirs = oh.DataDirectory[:]
	}
	im.Entry = im.ImageBase + uint64(entryRVA)

	for _, s := range f.Sections {
		d, err := s.Data()
		if err != nil {
			continue
		}
		im.segs = append(im.segs, segment{
			va:   im.ImageBase + uint64(s.VirtualAddress),
			data: d,
			exec: s.Characteristics&0x20000000 != 0,
		})
	}

	im.loadSymbols(f)
	im.loadImports(dataDirs)

	// Seeds: entry point, then symbols that fall in an executable region.
	im.seeds = append(im.seeds, im.Entry)
	for va := range im.syms {
		im.seeds = append(im.seeds, va)
	}
	return im, nil
}

// ReadAt returns up to 16 bytes starting at VA, and how many were available.
func (im *Image) ReadAt(va uint64) ([]byte, bool) {
	for _, s := range im.segs {
		if va >= s.va && va < s.va+uint64(len(s.data)) {
			off := va - s.va
			end := off + 16
			if end > uint64(len(s.data)) {
				end = uint64(len(s.data))
			}
			return s.data[off:end], true
		}
	}
	return nil, false
}

// Exec reports whether VA falls in an executable section.
func (im *Image) Exec(va uint64) bool {
	for _, s := range im.segs {
		if s.exec && va >= s.va && va < s.va+uint64(len(s.data)) {
			return true
		}
	}
	return false
}

// APIAt returns the import name for an IAT slot VA, if any.
func (im *Image) APIAt(va uint64) (string, bool) {
	n, ok := im.iat[va]
	return n, ok
}

// SymAt returns the symbol name at a VA, if known.
func (im *Image) SymAt(va uint64) (string, bool) {
	n, ok := im.syms[va]
	return n, ok
}

// Seeds returns the candidate function-start VAs.
func (im *Image) Seeds() []uint64 { return im.seeds }

func (im *Image) loadSymbols(f *pe.File) {
	for _, s := range f.Symbols {
		if s.SectionNumber <= 0 || int(s.SectionNumber) > len(f.Sections) {
			continue
		}
		sec := f.Sections[s.SectionNumber-1]
		if sec.Characteristics&0x20000000 == 0 { // not executable
			continue
		}
		va := im.ImageBase + uint64(sec.VirtualAddress) + uint64(s.Value)
		if _, seen := im.syms[va]; !seen && s.Name != "" {
			im.syms[va] = s.Name
		}
	}
}

// loadImports walks the import directory (data dir index 1) and records, for
// each imported function, the VA of its IAT slot -> name. Works for 32- and
// 64-bit thunks.
func (im *Image) loadImports(dd []pe.DataDirectory) {
	if len(dd) <= 1 || dd[1].VirtualAddress == 0 {
		return
	}
	thunkSize := uint64(4)
	ordinalFlag := uint64(0x80000000)
	if im.Bits == 64 {
		thunkSize = 8
		ordinalFlag = 0x8000000000000000
	}
	descVA := im.ImageBase + uint64(dd[1].VirtualAddress)
	for d := 0; d < 4096; d++ {
		desc, ok := im.readN(descVA+uint64(d*20), 20)
		if !ok || len(desc) < 20 {
			return
		}
		origThunk := binary.LittleEndian.Uint32(desc[0:])
		nameRVA := binary.LittleEndian.Uint32(desc[12:])
		firstThunk := binary.LittleEndian.Uint32(desc[16:])
		if origThunk == 0 && firstThunk == 0 && nameRVA == 0 {
			return // terminator
		}
		intRVA := origThunk
		if intRVA == 0 {
			intRVA = firstThunk // bound imports: INT missing, walk IAT
		}
		intVA := im.ImageBase + uint64(intRVA)
		iatVA := im.ImageBase + uint64(firstThunk)
		for i := 0; i < 8192; i++ {
			raw, ok := im.readN(intVA+uint64(i)*thunkSize, int(thunkSize))
			if !ok {
				break
			}
			var val uint64
			if thunkSize == 8 {
				val = binary.LittleEndian.Uint64(raw)
			} else {
				val = uint64(binary.LittleEndian.Uint32(raw))
			}
			if val == 0 {
				break
			}
			slotVA := iatVA + uint64(i)*thunkSize
			if val&ordinalFlag != 0 {
				im.iat[slotVA] = ordinalName(val & 0xFFFF)
				continue
			}
			// val is an RVA to IMAGE_IMPORT_BY_NAME: 2-byte hint then ASCIIZ.
			name := im.readCString(im.ImageBase + val + 2)
			if name != "" {
				im.iat[slotVA] = name
			}
		}
	}
}

func (im *Image) readN(va uint64, n int) ([]byte, bool) {
	for _, s := range im.segs {
		if va >= s.va && va+uint64(n) <= s.va+uint64(len(s.data)) {
			off := va - s.va
			return s.data[off : off+uint64(n)], true
		}
	}
	return nil, false
}

func (im *Image) readCString(va uint64) string {
	var out []byte
	for i := 0; i < 512; i++ {
		b, ok := im.readN(va+uint64(i), 1)
		if !ok || b[0] == 0 {
			break
		}
		out = append(out, b[0])
	}
	return string(out)
}

func ordinalName(ord uint64) string {
	return "ordinal#" + itoa(ord)
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
