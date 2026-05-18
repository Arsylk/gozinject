package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"strings"
)

// GetElfMappingSpan computes total memory span (first LOAD start to last LOAD end)
// for an ELF shared library. Returns page-aligned (start_vaddr, end_vaddr).
func GetElfMappingSpan(libPath string) (uint64, uint64, error) {
	raw, err := os.ReadFile(libPath)
	if err != nil {
		return 0, 0, err
	}
	f, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	var minStart, maxEnd uint64 = ^uint64(0), 0
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		start := prog.Vaddr
		end := prog.Vaddr + prog.Memsz
		if start < minStart {
			minStart = start
		}
		if end > maxEnd {
			maxEnd = end
		}
	}
	if minStart == ^uint64(0) {
		return 0, 0, fmt.Errorf("no PT_LOAD in %s", libPath)
	}
	minStart &^= 0xfff
	maxEnd = (maxEnd + 0xfff) &^ 0xfff
	return minStart, maxEnd, nil
}

func FindSymbolOffset(libPath string, symbolName string) (uint64, error) {
	f, err := os.Open(libPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	ef, err := elf.NewFile(f)
	if err != nil {
		return 0, err
	}

	// Try dynamic symbols first (usually what we want for shared libs)
	symbols, err := ef.DynamicSymbols()
	if err == nil {
		for _, sym := range symbols {
			if sym.Name == symbolName {
				return sym.Value, nil
			}
		}
	}

	// Fallback to regular symbols (includes LOCAL/HIDDEN)
	symbols, err = ef.Symbols()
	if err == nil {
		for _, sym := range symbols {
			if sym.Name == symbolName {
				return sym.Value, nil
			}
		}
	}

	return 0, fmt.Errorf("symbol %s not found in %s", symbolName, libPath)
}

// FindSymbolOffsetPrefix finds a symbol by prefix match in the regular symbol table.
// This is needed for symbols with LLVM suffixes like "__dl__ZL6solist.llvm.XXXXX".
func FindSymbolOffsetPrefix(libPath string, prefix string) (uint64, string, error) {
	f, err := os.Open(libPath)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	ef, err := elf.NewFile(f)
	if err != nil {
		return 0, "", err
	}

	// Search regular symbols (LOCAL/HIDDEN symbols are only here)
	symbols, err := ef.Symbols()
	if err == nil {
		for _, sym := range symbols {
			if strings.HasPrefix(sym.Name, prefix) && sym.Value != 0 {
				return sym.Value, sym.Name, nil
			}
		}
	}

	// Also check dynamic symbols
	symbols, err = ef.DynamicSymbols()
	if err == nil {
		for _, sym := range symbols {
			if strings.HasPrefix(sym.Name, prefix) && sym.Value != 0 {
				return sym.Value, sym.Name, nil
			}
		}
	}

	return 0, "", fmt.Errorf("symbol with prefix %s not found in %s", prefix, libPath)
}

func FindSymbolAddress(pid int, libPath string, libName string, symbolName string) (uint64, error) {
	base, err := GetModuleBase(pid, libName)
	if err != nil {
		return 0, err
	}

	offset, err := FindSymbolOffset(libPath, symbolName)
	if err != nil {
		return 0, err
	}

	return base + offset, nil
}
