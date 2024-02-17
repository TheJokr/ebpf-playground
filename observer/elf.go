package main

import (
	"debug/elf"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
)

var (
	ErrNoSymbol  = link.ErrNoSymbol
	ErrNoSegment = errors.New("not in memory")
)

type FunctionOffsets struct {
	Address uint64
	Returns []uint64
}

type ELFFile struct {
	f     *elf.File
	progs []*elf.Prog
	funcs map[string]elf.Symbol
}

func OpenELFFile(path string) (*ELFFile, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("parse ELF file: %w", err)
	}

	ef := &ELFFile{f: f}
	if err := ef.loadFuncs(); err != nil {
		return nil, fmt.Errorf("parse symbol table: %w", err)
	}

	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && (p.Flags&elf.PF_X) != 0 {
			ef.progs = append(ef.progs, p)
		}
	}
	return ef, nil
}

func (ef *ELFFile) loadFuncs() error {
	syms, err := ef.f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return err
	}
	dynsyms, err := ef.f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return err
	}

	ef.funcs = make(map[string]elf.Symbol)
	for _, symSlice := range [][]elf.Symbol{syms, dynsyms} {
		for _, s := range symSlice {
			if elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Size != 0 {
				ef.funcs[s.Name] = s
			}
		}
	}
	return nil
}

func (ef *ELFFile) Close() error {
	return ef.f.Close()
}

func (ef *ELFFile) findProg(vaddr uint64) *elf.Prog {
	for _, p := range ef.progs {
		if p.Vaddr <= vaddr && vaddr < (p.Vaddr+p.Memsz) {
			return p
		}
	}
	return nil
}

func (ef *ELFFile) FindFunction(name string) (FunctionOffsets, error) {
	sym, ok := ef.funcs[name]
	if !ok {
		return FunctionOffsets{}, fmt.Errorf("func %s: %w", name, ErrNoSymbol)
	}

	prog := ef.findProg(sym.Value)
	if prog == nil {
		return FunctionOffsets{}, fmt.Errorf("func %s: %w", name, ErrNoSegment)
	}

	off := sym.Value - prog.Vaddr
	insns := make([]byte, sym.Size)
	if _, err := prog.ReadAt(insns, int64(off)); err != nil {
		return FunctionOffsets{}, fmt.Errorf("read func %s: %w", name, err)
	}

	rets, err := findReturns(insns)
	if err != nil {
		return FunctionOffsets{}, fmt.Errorf("decode func %s: %w", name, err)
	}

	fileOff := prog.Off + off
	return FunctionOffsets{Address: fileOff, Returns: rets}, nil
}
