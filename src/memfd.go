package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// MemfdInject implements the memfd_create-based injection path.
// Instead of staging a file on disk, the payload is loaded entirely from
// an anonymous memory-backed file descriptor.
//
// Flow:
//  1. Inject a syscall stub into zygote that calls memfd_create("jit-cache", MFD_CLOEXEC)
//  2. Read back the fd number from the mailbox
//  3. Write the .so contents into the memfd via a write() loop stub
//  4. The child inherits the memfd after fork (since it's created before fork)
//  5. Shellcode calls dlopen("/proc/self/fd/<N>", RTLD_NOW)
//
// Result: maps shows "/memfd:jit-cache (deleted)" which is indistinguishable
// from legitimate ART JIT code cache entries.

// CreateMemfdInZygote injects a memfd_create syscall into zygote and returns
// the resulting fd number. The memfd will be inherited by all children.
func CreateMemfdInZygote(zygotePid int, trapAddr uint64, mailboxAddr uint64) (int, error) {
	LogDebug("creating memfd in zygote", "pid", zygotePid)

	// Clear mailbox
	if err := WritePointer(zygotePid, mailboxAddr, 0); err != nil {
		return 0, fmt.Errorf("cannot clear mailbox: %w", err)
	}

	// Build memfd_create shellcode
	stub := buildMemfdCreateStub(mailboxAddr)

	// Backup the trap region
	backup, err := ReadMem(zygotePid, trapAddr, len(stub))
	if err != nil {
		return 0, fmt.Errorf("cannot backup trap: %w", err)
	}

	// Write the stub
	if err := WriteMem(zygotePid, trapAddr, stub); err != nil {
		return 0, fmt.Errorf("cannot write memfd stub: %w", err)
	}

	// Retry hijack — zygote threads may need a moment to settle into a syscall
	var hijackErr error
	for attempt := 0; attempt < 20; attempt++ {
		hijackErr = hijackThreadForExecution(zygotePid, trapAddr)
		if hijackErr == nil {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if hijackErr != nil {
		_ = WriteMem(zygotePid, trapAddr, backup)
		return 0, fmt.Errorf("thread hijack for memfd failed: %w", hijackErr)
	}

	// Poll mailbox for the fd result
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		val, err := ReadPointer(zygotePid, mailboxAddr)
		if err == nil && val != 0 {
			_ = WriteMem(zygotePid, trapAddr, backup)
			// The fd is stored as (fd + 1) to distinguish from "not ready" (0)
			fd := int(val) - 1
			if fd < 0 {
				return 0, fmt.Errorf("memfd_create returned error: %d", fd)
			}
			LogInfo("memfd created in zygote", "fd", fd)
			return fd, nil
		}
		time.Sleep(5 * time.Millisecond)
	}

	_ = WriteMem(zygotePid, trapAddr, backup)
	return 0, fmt.Errorf("memfd_create mailbox timeout")
}

// WritePayloadToMemfd writes the .so file contents into the memfd by injecting
// write() syscall stubs into the target process.
func WritePayloadToMemfd(pid int, fd int, payloadPath string, trapAddr uint64, mailboxAddr uint64) error {
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("cannot read payload: %w", err)
	}

	LogInfo("writing payload to memfd", "size", len(payload), "fd", fd)

	// Find a writable region to stage chunk data
	rwBase, err := GetModuleRWSegment(pid, "libandroid_runtime.so")
	if err != nil {
		return fmt.Errorf("cannot find staging area: %w", err)
	}
	stagingAddr := rwBase + 0x2000

	const chunkSize = 4096

	for offset := 0; offset < len(payload); offset += chunkSize {
		end := offset + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[offset:end]

		// Stage chunk data in target memory
		if err := WriteMem(pid, stagingAddr, chunk); err != nil {
			return fmt.Errorf("cannot stage chunk at offset %d: %w", offset, err)
		}

		// Clear mailbox
		_ = WritePointer(pid, mailboxAddr, 0)

		// Build write() stub
		stub := buildWriteStub(fd, stagingAddr, uint64(len(chunk)), mailboxAddr)

		backup, err := ReadMem(pid, trapAddr, len(stub))
		if err != nil {
			return fmt.Errorf("cannot backup trap: %w", err)
		}

		if err := WriteMem(pid, trapAddr, stub); err != nil {
			return fmt.Errorf("cannot write write-stub: %w", err)
		}

		// Retry hijack — same thread may need a moment to re-enter svc
		var hijackErr error
		for attempt := 0; attempt < 10; attempt++ {
			hijackErr = hijackThreadForExecution(pid, trapAddr)
			if hijackErr == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if hijackErr != nil {
			_ = WriteMem(pid, trapAddr, backup)
			return fmt.Errorf("thread hijack for write failed at offset %d: %w", offset, hijackErr)
		}

		// Wait for completion
		deadline := time.Now().Add(3 * time.Second)
		done := false
		for time.Now().Before(deadline) {
			val, _ := ReadPointer(pid, mailboxAddr)
			if val != 0 {
				done = true
				break
			}
			time.Sleep(2 * time.Millisecond)
		}

		_ = WriteMem(pid, trapAddr, backup)
		if !done {
			return fmt.Errorf("write stub timeout at offset %d", offset)
		}
	}

	LogInfo("payload written to memfd", "total_bytes", len(payload))
	return nil
}

// buildMemfdCreateStub creates ARM64 shellcode for memfd_create("jit-cache", MFD_CLOEXEC).
func buildMemfdCreateStub(mailboxAddr uint64) []byte {
	stub := make([]byte, 256)

	// Save registers
	binary.LittleEndian.PutUint32(stub[0x00:], 0xd10203ff) // sub sp, sp, #128
	binary.LittleEndian.PutUint32(stub[0x04:], 0xa90007e0) // stp x0, x1, [sp, #0]
	binary.LittleEndian.PutUint32(stub[0x08:], 0xa9010fe2) // stp x2, x3, [sp, #16]
	binary.LittleEndian.PutUint32(stub[0x0c:], 0xf90023e8) // str x8, [sp, #64]
	binary.LittleEndian.PutUint32(stub[0x10:], 0xf90027fe) // str x30, [sp, #72]

	// memfd_create("jit-cache", MFD_CLOEXEC)
	binary.LittleEndian.PutUint32(stub[0x14:], encodeAdr(0, 0x14, 0xB0)) // adr x0, name_str
	binary.LittleEndian.PutUint32(stub[0x18:], 0xd2800021)               // mov x1, #1 (MFD_CLOEXEC)
	binary.LittleEndian.PutUint32(stub[0x1c:], 0xd28022e8)               // mov x8, #279 (SYS_memfd_create)
	binary.LittleEndian.PutUint32(stub[0x20:], 0xd4000001)               // svc #0

	// Store (fd + 1) to mailbox
	binary.LittleEndian.PutUint32(stub[0x24:], 0x91000400)               // add x0, x0, #1
	binary.LittleEndian.PutUint32(stub[0x28:], encodeLdr(1, 0x28, 0xA0)) // ldr x1, [mailbox]
	binary.LittleEndian.PutUint32(stub[0x2c:], 0xf9000020)               // str x0, [x1]

	// Restore hijacked instruction
	binary.LittleEndian.PutUint32(stub[0x30:], encodeLdr(9, 0x30, 0xE0))  // ldr x9, [orig_pc]
	binary.LittleEndian.PutUint32(stub[0x34:], encodeLdr(10, 0x34, 0xE8)) // ldr x10, [orig_instr]
	binary.LittleEndian.PutUint32(stub[0x38:], 0xb9000129)                // str w10, [x9]

	// Restore registers
	binary.LittleEndian.PutUint32(stub[0x3c:], 0xa94007e0) // ldp x0, x1, [sp, #0]
	binary.LittleEndian.PutUint32(stub[0x40:], 0xa9410fe2) // ldp x2, x3, [sp, #16]
	binary.LittleEndian.PutUint32(stub[0x44:], 0xf94023e8) // ldr x8, [sp, #64]
	binary.LittleEndian.PutUint32(stub[0x48:], 0xf94027fe) // ldr x30, [sp, #72]
	binary.LittleEndian.PutUint32(stub[0x4c:], 0x910203ff) // add sp, sp, #128

	// Branch back to original PC
	binary.LittleEndian.PutUint32(stub[0x50:], 0xd61f0120) // br x9

	// [0xA0] mailbox address
	binary.LittleEndian.PutUint64(stub[0xA0:], mailboxAddr)
	// [0xB0] name string: "jit-cache\0"
	copy(stub[0xB0:], "jit-cache\x00")
	// [0xE0] orig_pc — filled by hijackThreadForExecution
	// [0xE8] orig_instr — filled by hijackThreadForExecution

	return stub
}

// buildWriteStub creates ARM64 shellcode for write(fd, buf, count).
func buildWriteStub(fd int, bufAddr uint64, count uint64, mailboxAddr uint64) []byte {
	stub := make([]byte, 256)

	// Save registers
	binary.LittleEndian.PutUint32(stub[0x00:], 0xd10203ff) // sub sp, sp, #128
	binary.LittleEndian.PutUint32(stub[0x04:], 0xa90007e0) // stp x0, x1, [sp, #0]
	binary.LittleEndian.PutUint32(stub[0x08:], 0xa9010fe2) // stp x2, x3, [sp, #16]
	binary.LittleEndian.PutUint32(stub[0x0c:], 0xf90023e8) // str x8, [sp, #64]
	binary.LittleEndian.PutUint32(stub[0x10:], 0xf90027fe) // str x30, [sp, #72]

	// write(fd, buf, count) — SYS_write = 64
	binary.LittleEndian.PutUint32(stub[0x14:], encodeMov(0, uint16(fd))) // mov x0, #fd
	binary.LittleEndian.PutUint32(stub[0x18:], encodeLdr(1, 0x18, 0xA0)) // ldr x1, [bufAddr]
	binary.LittleEndian.PutUint32(stub[0x1c:], encodeLdr(2, 0x1c, 0xA8)) // ldr x2, [count]
	binary.LittleEndian.PutUint32(stub[0x20:], 0xd2800808)               // mov x8, #64 (SYS_write)
	binary.LittleEndian.PutUint32(stub[0x24:], 0xd4000001)               // svc #0

	// Signal completion
	binary.LittleEndian.PutUint32(stub[0x28:], encodeLdr(1, 0x28, 0xB0)) // ldr x1, [mailbox]
	binary.LittleEndian.PutUint32(stub[0x2c:], 0xd2800020)               // mov x0, #1
	binary.LittleEndian.PutUint32(stub[0x30:], 0xf9000020)               // str x0, [x1]

	// Restore hijacked instruction
	binary.LittleEndian.PutUint32(stub[0x34:], encodeLdr(9, 0x34, 0xE0))  // ldr x9, [orig_pc]
	binary.LittleEndian.PutUint32(stub[0x38:], encodeLdr(10, 0x38, 0xE8)) // ldr x10, [orig_instr]
	binary.LittleEndian.PutUint32(stub[0x3c:], 0xb9000129)                // str w10, [x9]

	// Restore registers
	binary.LittleEndian.PutUint32(stub[0x40:], 0xa94007e0) // ldp x0, x1, [sp, #0]
	binary.LittleEndian.PutUint32(stub[0x44:], 0xa9410fe2) // ldp x2, x3, [sp, #16]
	binary.LittleEndian.PutUint32(stub[0x48:], 0xf94023e8) // ldr x8, [sp, #64]
	binary.LittleEndian.PutUint32(stub[0x4c:], 0xf94027fe) // ldr x30, [sp, #72]
	binary.LittleEndian.PutUint32(stub[0x50:], 0x910203ff) // add sp, sp, #128

	// Branch back
	binary.LittleEndian.PutUint32(stub[0x54:], 0xd61f0120) // br x9

	// [0xA0] Data slots
	binary.LittleEndian.PutUint64(stub[0xA0:], bufAddr)     // buffer address
	binary.LittleEndian.PutUint64(stub[0xA8:], count)       // byte count
	binary.LittleEndian.PutUint64(stub[0xB0:], mailboxAddr) // mailbox
	// [0xE0] orig_pc — filled by hijackThreadForExecution
	// [0xE8] orig_instr — filled by hijackThreadForExecution

	return stub
}

// RunMemfdInjector is the alternative injection path using memfd_create.
func RunMemfdInjector(pkgName string, payloadPath string, zygotePid int, mainActivity string) (int, error) {
	LogInfo("starting memfd injector", "package", pkgName, "mode", "memfd")

	libAndroidPath := "/system/lib64/libandroid_runtime.so"
	setArgV0Addr, err := FindSymbolAddress(zygotePid, libAndroidPath, "libandroid_runtime.so", "_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring")
	if err != nil {
		return 0, err
	}

	rwBase, err := GetModuleRWSegment(zygotePid, "libandroid_runtime.so")
	if err != nil {
		return 0, fmt.Errorf("failed to find RW segment: %v", err)
	}
	mailboxAddr := rwBase + 0x1FF0
	_ = WritePointer(zygotePid, mailboxAddr, 0)

	linkerBase, _ := GetModuleBase(zygotePid, "linker64")
	dlopenOffset, _ := FindSymbolOffset("/system/bin/linker64", "__loader_dlopen")
	dlopenAddr := linkerBase + dlopenOffset

	// Step 1: Create memfd in zygote
	memfd, err := CreateMemfdInZygote(zygotePid, setArgV0Addr, mailboxAddr)
	if err != nil {
		return 0, fmt.Errorf("memfd creation failed: %w", err)
	}

	// Step 2: Write payload into the memfd
	err = WritePayloadToMemfd(zygotePid, memfd, payloadPath, setArgV0Addr, mailboxAddr)
	if err != nil {
		return 0, fmt.Errorf("memfd write failed: %w", err)
	}

	// Step 3: Set up dlopen trap using memfd path
	origBackup, _ := ReadMem(zygotePid, setArgV0Addr, 256)
	_ = WritePointer(zygotePid, mailboxAddr, 0)
	trap := BuildMemfdShellcode(zygotePid, setArgV0Addr, dlopenAddr, mailboxAddr, memfd, origBackup)

	// Record existing children
	out, _ := exec.Command("pgrep", "-P", strconv.Itoa(zygotePid)).Output()
	prevChildren := make(map[int]bool)
	for _, f := range strings.Fields(string(out)) {
		pid, _ := strconv.Atoi(f)
		prevChildren[pid] = true
	}

	// Apply trap
	WriteMem(zygotePid, setArgV0Addr, trap)
	defer func() {
		WriteMem(zygotePid, setArgV0Addr, origBackup[:256])
	}()

	// Launch app
	exec.Command("am", "start", "-n", mainActivity).Run()

	// Wait for child
	var childPid int
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out, _ = exec.Command("pgrep", "-P", strconv.Itoa(zygotePid)).Output()
		for _, f := range strings.Fields(string(out)) {
			pid, _ := strconv.Atoi(f)
			if !prevChildren[pid] {
				childPid = pid
				break
			}
		}
		if childPid != 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if childPid == 0 {
		return 0, fmt.Errorf("timeout identifying child process")
	}
	LogInfo("identified child", "pid", childPid)

	// Poll mailbox in child
	zygoteBase, _ := GetModuleBase(zygotePid, "libandroid_runtime.so")
	childBase, _ := GetModuleBase(childPid, "libandroid_runtime.so")
	childMailboxAddr := childBase + (mailboxAddr - zygoteBase)

	for time.Now().Before(deadline) {
		if !IsProcessAlive(childPid) {
			LogWarn("child exited before memfd stealth sequence", "pid", childPid)
			fallbackPid, err := FindNewestChildPid(zygotePid, pkgName, 1500*time.Millisecond)
			if err == nil && fallbackPid != childPid {
				LogInfo("reattached to relaunched child", "pid", fallbackPid)
				childPid = fallbackPid
				childBase, err = GetModuleBase(childPid, "libandroid_runtime.so")
				if err == nil {
					childMailboxAddr = childBase + (mailboxAddr - zygoteBase)
					continue
				}
			}
			return childPid, fmt.Errorf("child process exited before memfd handshake")
		}

		val, err := ReadPointer(childPid, childMailboxAddr)
		if err == nil && val != 0 {
			LogInfo("memfd handshake successful", "handle", val)

			// Best-effort soinfo unlinking for memfd paths.
			time.Sleep(50 * time.Millisecond)
			fdPath := fmt.Sprintf("/proc/self/fd/%d", memfd)
			if _, err := UnlinkSoinfo(childPid, fdPath, DefaultAPILevel); err != nil {
				LogWarn("soinfo unlink failed (non-fatal)", "error", err)
			}
			// Second unlink for name-based match (memfd path in maps)
			_, _ = UnlinkSoinfo(childPid, "memfd:jit-cache", DefaultAPILevel)

			return childPid, nil
		}
		time.Sleep(5 * time.Millisecond)
	}

	return childPid, fmt.Errorf("memfd handshake timeout")
}
