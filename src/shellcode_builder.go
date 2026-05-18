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
// Post-injection steps (soinfo unlink + vma_hide) are handled by the injector
// from userspace (via UnlinkSoinfo → hideVma), not from shellcode.
func BuildAgnosticShellcode(zygotePid int, setArgV0Addr uint64, dlopenAddr uint64, mailboxAddr uint64, libPath string, origBackup []byte) []byte {
	trap := make([]byte, 512)

	// [0x00] PID Check — skip to parent path if we're zygote
	binary.LittleEndian.PutUint32(trap[0x00:], 0xd2801588)                               // mov x8, #172 (getpid)
	binary.LittleEndian.PutUint32(trap[0x04:], 0xd4000001)                               // svc #0
	binary.LittleEndian.PutUint32(trap[0x08:], 0x52800001|(uint32(zygotePid&0xffff)<<5)) // mov w1, zygotePid[15:0]
	binary.LittleEndian.PutUint32(trap[0x0c:], 0x6b01001f)                               // cmp w0, w1
	binary.LittleEndian.PutUint32(trap[0x10:], 0x540004a0)                               // b.eq +0x94 → parent at 0xa4

	// [0x14] Child Path — dlopen only, no unlink
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

	// [0x38-0x4b] NOP'd — unlinkat and vma_hide handled by injector post-handshake
	binary.LittleEndian.PutUint32(trap[0x38:], 0xd503201f) // nop
	binary.LittleEndian.PutUint32(trap[0x3c:], 0xd503201f) // nop
	binary.LittleEndian.PutUint32(trap[0x40:], 0xd503201f) // nop
	binary.LittleEndian.PutUint32(trap[0x44:], 0xd503201f) // nop
	binary.LittleEndian.PutUint32(trap[0x48:], 0xd503201f) // nop

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
// The fd is closed after dlopen so /proc/self/maps shows
// /memfd:jit-cache (deleted) — indistinguishable from ART JIT cache entries.
func BuildMemfdShellcode(zygotePid int, setArgV0Addr uint64, dlopenAddr uint64, mailboxAddr uint64, memfd int, origBackup []byte) []byte {
	trap := make([]byte, 512)

	// Build /proc/self/fd/<N> string
	fdPath := fmt.Sprintf("/proc/self/fd/%d", memfd)

	// [0x00] PID Check — b.eq offset updated for parent at 0x70 (was 0x60)
	binary.LittleEndian.PutUint32(trap[0x00:], 0xd2801588)                               // mov x8, #172 (getpid)
	binary.LittleEndian.PutUint32(trap[0x04:], 0xd4000001)                               // svc #0
	binary.LittleEndian.PutUint32(trap[0x08:], 0x52800001|(uint32(zygotePid&0xffff)<<5)) // mov w1, zygotePid[15:0]
	binary.LittleEndian.PutUint32(trap[0x0c:], 0x6b01001f)                               // cmp w0, w1
	binary.LittleEndian.PutUint32(trap[0x10:], 0x54000300)                               // b.eq +0x60 → parent at 0x70

	// [0x14] Child Path — dlopen then close(fd) then mailbox
	binary.LittleEndian.PutUint32(trap[0x14:], 0xd10103ff)                // sub sp, sp, #64
	binary.LittleEndian.PutUint32(trap[0x18:], 0xa90007e0)                // stp x0, x1, [sp, #0]
	binary.LittleEndian.PutUint32(trap[0x1c:], 0xa9010fe2)                // stp x2, x3, [sp, #16]
	binary.LittleEndian.PutUint32(trap[0x20:], 0xf90013fe)                // str x30, [sp, #32]
	binary.LittleEndian.PutUint32(trap[0x24:], encodeAdr(0, 0x24, 0x150)) // adr x0, fdPath
	binary.LittleEndian.PutUint32(trap[0x28:], 0xd2800041)                // mov x1, #2 (RTLD_NOW)
	binary.LittleEndian.PutUint32(trap[0x2c:], encodeLdr(8, 0x2c, 0x110)) // ldr x8, dlopenAddr
	binary.LittleEndian.PutUint32(trap[0x30:], 0xd63f0100)                // blr x8

	// close(memfd) — so maps shows (deleted), indistinguishable from ART
	binary.LittleEndian.PutUint32(trap[0x34:], 0xaa0003e9)                  // mov x9, x0 (save handle)
	binary.LittleEndian.PutUint32(trap[0x38:], encodeMov(0, uint16(memfd))) // mov x0, #memfd
	binary.LittleEndian.PutUint32(trap[0x3c:], 0xd2800728)                  // mov x8, #57 (SYS_close)
	binary.LittleEndian.PutUint32(trap[0x40:], 0xd4000001)                  // svc #0
	binary.LittleEndian.PutUint32(trap[0x44:], 0xaa0903e0)                  // mov x0, x9 (restore handle)

	// Write handle to mailbox
	binary.LittleEndian.PutUint32(trap[0x48:], encodeLdr(1, 0x48, 0x120)) // ldr x1, mailboxAddr
	binary.LittleEndian.PutUint32(trap[0x4c:], 0xf9000020)                // str x0, [x1]

	// Restore and return
	binary.LittleEndian.PutUint32(trap[0x50:], 0xa94007e0) // ldp x0, x1, [sp, #0]
	binary.LittleEndian.PutUint32(trap[0x54:], 0xa9410fe2) // ldp x2, x3, [sp, #16]
	binary.LittleEndian.PutUint32(trap[0x58:], 0xf94013fe) // ldr x30, [sp, #32]
	binary.LittleEndian.PutUint32(trap[0x5c:], 0x910103ff) // add sp, sp, #64
	binary.LittleEndian.PutUint32(trap[0x60:], 0xd65f03c0) // ret

	// Pad gap [0x64-0x6f]
	for i := 0x64; i < 0x70; i += 4 {
		binary.LittleEndian.PutUint32(trap[i:], 0xd503201f) // nop
	}

	// [0x70] Parent Path
	copy(trap[0x70:0x90], origBackup[:32])
	binary.LittleEndian.PutUint32(trap[0x90:], encodeLdr(8, 0x90, 0x100)) // ldr x8, returnTarget
	binary.LittleEndian.PutUint32(trap[0x94:], 0xd61f0100)                // br x8

	// [0x100] Data Slots
	binary.LittleEndian.PutUint64(trap[0x100:], setArgV0Addr+32)
	binary.LittleEndian.PutUint64(trap[0x110:], dlopenAddr)
	binary.LittleEndian.PutUint64(trap[0x120:], mailboxAddr)
	// [0x150] fd path string
	copy(trap[0x150:], fdPath)

	return trap
}
