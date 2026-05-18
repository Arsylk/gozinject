package main

import (
	"fmt"
	"os"
	"strings"
)

// SoinfoOffsets holds version-specific offsets into the soinfo struct.
type SoinfoOffsets struct {
	Next                int
	Realpath            int
	StdStringInlineSize int
}

func GetSoinfoOffsets(apiLevel int) SoinfoOffsets {
	switch {
	case apiLevel >= 34:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x1A8, StdStringInlineSize: 23}
	case apiLevel >= 33:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x1A0, StdStringInlineSize: 23}
	case apiLevel >= 31:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x198, StdStringInlineSize: 23}
	case apiLevel >= 30:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x190, StdStringInlineSize: 23}
	case apiLevel >= 29:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x188, StdStringInlineSize: 23}
	default:
		return SoinfoOffsets{Next: 0x28, Realpath: 0x180, StdStringInlineSize: 23}
	}
}

func readSoinfoRealpath(pid int, soinfoAddr uint64, offsets SoinfoOffsets) (string, error) {
	strAddr := soinfoAddr + uint64(offsets.Realpath)
	strData, err := ReadMem(pid, strAddr, 32)
	if err != nil {
		return "", err
	}

	isLong := (strData[0] & 1) != 0
	if isLong {
		ptr := uint64(strData[16]) | uint64(strData[17])<<8 | uint64(strData[18])<<16 |
			uint64(strData[19])<<24 | uint64(strData[20])<<32 | uint64(strData[21])<<40 |
			uint64(strData[22])<<48 | uint64(strData[23])<<56
		if ptr == 0 {
			return "", nil
		}
		return ReadString(pid, ptr, 256)
	}

	length := int(strData[0] >> 1)
	if length > 22 {
		length = 22
	}
	if length == 0 {
		return "", nil
	}
	return string(strData[1 : 1+length]), nil
}

// SoinfoVmaInfo holds the base and end of a loaded soinfo mapping.
type SoinfoVmaInfo struct {
	Addr uint64 // soinfo node address
	Base uint64 // load address (from /proc/maps, page-aligned)
	End  uint64 // last mapped byte+1 (first VMA start to last VMA end)
}

// UnlinkSoinfo removes the specified library from the linker's soinfo linked list
// and returns the soinfo VMA info for vma_hide.
// findPayloadVmaRanges reads /proc/<pid>/maps and returns all individual VMA
// entries matching the payload path.
type payloadVmaRange struct {
	Start uint64
	End   uint64
	Perms string
}

func findPayloadVmaRanges(pid int, payloadPath string) ([]payloadVmaRange, error) {
	ranges, err := ParseMaps(pid)
	if err != nil {
		return nil, fmt.Errorf("parse maps: %w", err)
	}
	var result []payloadVmaRange
	for _, r := range ranges {
		if r.Path != "" && strings.Contains(r.Path, payloadPath) {
			result = append(result, payloadVmaRange{Start: r.Start, End: r.End, Perms: r.Perms})
			LogDebug("found payload mapping", "start", r.Start, "end", r.End, "perms", r.Perms)
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("payload path %q not found in maps", payloadPath)
	}
	return result, nil
}

// hideVma writes to /proc/vma_hide to hide a VMA range.
// Kernel requires "0x" prefix for hex addresses.
func hideVma(base uint64, end uint64) error {
	cmd := fmt.Sprintf("add 0x%x 0x%x\n", base, end)
	f, err := os.OpenFile("/proc/vma_hide", os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open /proc/vma_hide: %w", err)
	}
	defer f.Close()
	if _, err = f.WriteString(cmd); err != nil {
		return fmt.Errorf("write /proc/vma_hide: %w", err)
	}
	return nil
}

func UnlinkSoinfo(pid int, payloadPath string, apiLevel int) (*SoinfoVmaInfo, error) {
	offsets := GetSoinfoOffsets(apiLevel)

	linkerBase, err := GetModuleBase(pid, "linker64")
	if err != nil {
		return nil, fmt.Errorf("cannot find linker64: %w", err)
	}

	linkerPaths := []string{
		"/system/bin/linker64",
		"/apex/com.android.runtime/bin/linker64",
	}

	var solistAddr uint64
	for _, lpath := range linkerPaths {
		offset, name, err := FindSymbolOffsetPrefix(lpath, "__dl__ZL6solist")
		if err == nil {
			solistAddr = linkerBase + offset
			LogDebug("found solist symbol", "symbol", name, "addr", solistAddr)
			break
		}
	}

	if solistAddr == 0 {
		return nil, fmt.Errorf("cannot locate solist symbol in linker64")
	}

	headPtr, err := ReadPointer(pid, solistAddr)
	if err != nil {
		return nil, fmt.Errorf("cannot read solist head: %w", err)
	}
	if headPtr == 0 {
		return nil, fmt.Errorf("solist head is null")
	}

	LogDebug("walking soinfo list", "head", headPtr)

	var prevAddr uint64
	current := headPtr
	iterations := 0

	for current != 0 && iterations < 512 {
		iterations++

		path, err := readSoinfoRealpath(pid, current, offsets)
		if err != nil {
			// skip unreadable nodes
		} else if path != "" && strings.Contains(path, payloadPath) {
			LogInfo("found payload soinfo node", "addr", current, "path", path)

			// Find all individual payload VMAs and hide each one
			vmaRanges, err := findPayloadVmaRanges(pid, payloadPath)
			if err != nil {
				LogWarn("find payload VMA ranges failed", "error", err)
			}
			// Compute spanning range from found VMAs
			var vmaBase, vmaEnd uint64
			for _, vr := range vmaRanges {
				if vmaBase == 0 || vr.Start < vmaBase {
					vmaBase = vr.Start
				}
				if vr.End > vmaEnd {
					vmaEnd = vr.End
				}
				// Hide each VMA individually (kernel requires exact boundaries)
				if err := hideVma(vr.Start, vr.End); err != nil {
					LogWarn("vma_hide failed for segment", "start", vr.Start, "end", vr.End, "error", err)
				} else {
					LogInfo("hidden VMA segment", "start", vr.Start, "end", vr.End, "perms", vr.Perms)
				}
			}
			vmaInfo := &SoinfoVmaInfo{Addr: current, Base: vmaBase, End: vmaEnd}

			// Unlink from linked list
			targetNext, err := ReadPointer(pid, current+uint64(offsets.Next))
			if err != nil {
				return vmaInfo, fmt.Errorf("cannot read target next pointer: %w", err)
			}

			if prevAddr == 0 {
				if err := WritePointer(pid, solistAddr, targetNext); err != nil {
					return vmaInfo, fmt.Errorf("failed to update solist head: %w", err)
				}
			} else {
				if err := WritePointer(pid, prevAddr, targetNext); err != nil {
					return vmaInfo, fmt.Errorf("failed to patch prev->next: %w", err)
				}
			}

			LogInfo("soinfo unlinked successfully", "path", path)

			return vmaInfo, nil
		}

		prevAddr = current + uint64(offsets.Next)
		current, err = ReadPointer(pid, prevAddr)
		if err != nil {
			return nil, fmt.Errorf("cannot read next pointer at %#x: %w", prevAddr, err)
		}
	}

	if iterations >= 512 {
		return nil, fmt.Errorf("soinfo walk exceeded 512 iterations")
	}

	return nil, fmt.Errorf("payload %q not found in soinfo list", payloadPath)
}
