package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

type Elf struct {
	*elf.File
	path string
	dest string
}

type ElfProcessor struct {
	db        map[string]string
	files     chan string
	projects  chan string
	entries   map[string]*os.File
	filewg    sync.WaitGroup
	projectwg sync.WaitGroup
	nsymbols  atomic.Uint64
	nfiles    atomic.Uint64
	rootCmake *os.File
}

const DYN_SIZE = 0x10
const SYM_SIZE = 0x18
const NID_LENGTH = 11

type Phdr struct {
	*elf.Prog
}

type ElfTable struct {
	Phdr
	addr uint64
	size uint64
}

type DynamicInfo struct {
	fp     *elf.File
	strtab ElfTable
	symtab ElfTable
}

type Symbol struct {
	elf.Sym64
	Name string
}

type Dyn struct {
	buf       []byte
	ByteOrder binary.ByteOrder
	reader    io.Reader
}

func (sym *Symbol) Type() elf.SymType {
	return elf.SymType(sym.Info & 0xf)
}

func (sym *Symbol) Bind() elf.SymBind {
	return elf.SymBind(sym.Info >> 4)
}

func (phdr *Phdr) ReadAt(p []byte, off int64) (n int, err error) {
	return phdr.Prog.ReadAt(p, off-int64(phdr.Paddr))
}

func (tbl *ElfTable) ReadAt(p []byte, off int64) (n int, err error) {
	return tbl.Phdr.ReadAt(p, int64(tbl.addr)+off)
}

func (tbl *ElfTable) Read(p []byte) (n int, err error) {
	return tbl.ReadAt(p, 0)
}

func getProgContaining(fp *Elf, addr uint64) Phdr {
	for i := range fp.Progs {
		p := fp.Progs[i]
		if p.Paddr <= addr && (p.Paddr+p.Filesz) > addr {
			return Phdr{p}
		}
	}
	panic(fmt.Errorf("phdr containing %d not found", addr))
}

func getSymtabSize(fp *Elf, hash uint64) uint64 {
	p := getProgContaining(fp, uint64(hash))
	buf := make([]byte, 4)
	_, err := p.ReadAt(buf, int64(hash))
	if err != nil {
		panic(err)
	}
	return uint64(fp.ByteOrder.Uint32(buf))
}

func (info *DynamicInfo) getString(n int) string {
	buf := make([]byte, NID_LENGTH)
	_, err := info.strtab.ReadAt(buf, int64(n))
	if err != nil {
		panic(err)
	}
	return string(buf)
}

func (info *DynamicInfo) getSymbol(n int) Symbol {
	var sym Symbol
	buf := make([]byte, SYM_SIZE)
	_, err := info.symtab.ReadAt(buf, int64(n*SYM_SIZE))
	if err != nil {
		panic(err)
	}
	sym.Sym64.Name = info.fp.ByteOrder.Uint32(buf)
	sym.Name = info.getString(int(sym.Sym64.Name))
	sym.Info = buf[4]
	sym.Other = buf[5]
	sym.Shndx = info.fp.ByteOrder.Uint16(buf[6:])
	sym.Value = info.fp.ByteOrder.Uint64(buf[8:])
	sym.Size = info.fp.ByteOrder.Uint64(buf[0x10:])
	return sym
}

func (d *Dyn) next() {
	_, err := d.reader.Read(d.buf)
	if err != nil {
		panic(err)
	}
}

func (d *Dyn) Tag() elf.DynTag {
	return elf.DynTag(d.ByteOrder.Uint64(d.buf))
}

func (d *Dyn) Value() uint64 {
	return d.ByteOrder.Uint64(d.buf[8:])
}

func newDyn(fp *Elf, r io.Reader) *Dyn {
	d := Dyn{make([]byte, DYN_SIZE), fp.ByteOrder, r}
	d.next()
	return &d
}

func (sym *Symbol) IsExported() bool {
	return sym.Value != 0
}

func getDynamicInfo(fp *Elf) *DynamicInfo {
	info := DynamicInfo{fp.File, ElfTable{}, ElfTable{}}
	for i := range fp.Progs {
		p := fp.Progs[i]
		if p.Type == elf.PT_DYNAMIC {
			for dyn := newDyn(fp, p.Open()); dyn.Tag() != elf.DT_NULL; dyn.next() {
				switch dyn.Tag() {
				case elf.DT_SYMTAB:
					addr := dyn.Value()
					info.symtab.addr = addr
					info.symtab.Prog = getProgContaining(fp, addr).Prog
				case elf.DT_HASH:
					addr := dyn.Value()
					info.symtab.size = getSymtabSize(fp, addr)
				case elf.DT_STRTAB:
					addr := dyn.Value()
					info.strtab.addr = addr
					info.strtab.Prog = getProgContaining(fp, addr).Prog
				case elf.DT_STRSZ:
					info.strtab.size = dyn.Value()
				}
			}
		}
	}
	return &info
}

func newElfProcessor() *ElfProcessor {
	aerolib := readAerolib()
	files := make(chan string, 16)
	projects := make(chan string, 16)
	entries := make(map[string]*os.File, 4)
	rootCmake := createFile(filepath.Join(getOutputPath(), CMAKE_FILENAME))
	return &ElfProcessor{
		db:        aerolib,
		files:     files,
		projects:  projects,
		entries:   entries,
		filewg:    sync.WaitGroup{},
		projectwg: sync.WaitGroup{},
		nsymbols:  atomic.Uint64{},
		nfiles:    atomic.Uint64{},
		rootCmake: rootCmake,
	}
}

func (p *ElfProcessor) Close() {
	p.rootCmake.Close()
}

func (p *ElfProcessor) CloseChannels() {
	close(p.files)
	close(p.projects)
}

func isBlacklistedFunction(fn string) bool {
	if strings.HasPrefix(fn, "__atomic") {
		return true
	}
	if strings.HasPrefix(fn, "__sync") {
		return true
	}
	return false
}

func (p *ElfProcessor) processElf(fp *Elf) {
	defer fp.Close()
	p.nfiles.Add(1)

	out := createFile(fp.dest)
	defer out.Close()

	info := getDynamicInfo(fp)
	names := make(map[string]bool, info.symtab.size)
	for i := 1; i < int(info.symtab.size); i++ {
		sym := info.getSymbol(i)
		if !sym.IsExported() {
			continue
		}

		switch sym.Type() {
		case elf.STT_FUNC:
			p.nsymbols.Add(1)

			if names[sym.Name] {
				continue
			}
			names[sym.Name] = true

			name := p.db[sym.Name]
			if name == "" || isBlacklistedFunction(name) {
				out.WriteString(fmt.Sprintf("// void %s(void) {}\n", sym.Name))
			} else {
				out.WriteString(fmt.Sprintf("void %s(void) {}\n", name))
			}
		case elf.STT_OBJECT:
			p.nsymbols.Add(1)
			name := p.db[sym.Name]
			if name == "" {
				out.WriteString(fmt.Sprintf("//unsigned char %s[0x%x];\n", sym.Name, sym.Size))
			} else if sym.Size == 0 {
				out.WriteString(fmt.Sprintf("//unsigned char %s[0x%x];\n", name, sym.Size))
			} else {
				out.WriteString(fmt.Sprintf("unsigned char %s[0x%x];\n", name, sym.Size))
			}
		default:
			continue
		}
	}
}
