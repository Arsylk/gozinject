---
inclusion: auto
---

# gozinject — Stealth Capabilities Development Guide

## Project Context

This is `gozinject`, an Android ARM64 process injector that works WITHOUT ptrace. It uses `/proc/pid/mem` for all memory operations and traps `setArgV0` in zygote64 to inject shared libraries into newly-spawned app processes.

The injector is written in Go, cross-compiled to `android/arm64` with `CGO_ENABLED=0`. It produces a single static binary.

## Architecture Summary

```
main.go              → CLI, stealth staging, payload lifecycle
injector.go          → Core orchestration: trap → spawn → mailbox handshake
shellcode_builder.go → ARM64 shellcode generation (512-byte payloads)
memory.go            → /proc/pid/mem read/write primitives
maps.go              → /proc/pid/maps parsing, module base resolution
elf.go               → ELF symbol resolution (dynamic + static)
utils.go             → Process discovery, activity resolution
stealth.go           → Stealth utilities (staging, naming, validation)
logger.go            → Structured logging with catppuccin theme
```

## Current Stealth State

Already implemented:
- Open → unlink → dlopen shellcode (file gone before anti-tamper runs)
- Innocuous payload staging names (`.org.chromium.<hex>.tmp`)
- Binary stripping (`-trimpath -ldflags="-s -w"`)
- Randomized injector name on device (`app_process_<hex>`)
- Post-injection cleanup of device artifacts
- No ptrace (evades TracerPid checks)
- Spawn-mode timing (injects before Application.onCreate)

## YOUR MISSION: Implement Advanced Stealth

You are to implement the following stealth capabilities, in priority order. All of these are **injector-side** — they operate via `/proc/pid/mem` writes after the initial dlopen handshake succeeds. No payload cooperation required.

---

### Phase 1: soinfo Unlinking (HIGH PRIORITY)

After dlopen succeeds and the mailbox confirms the handle, the injector must:

1. **Parse the linker's `soinfo` linked list** in the child process via `/proc/pid/mem`
2. **Find the payload's `soinfo` node** by matching the library path/name
3. **Unlink it** by patching the `next` pointer of the previous node to skip over it

This makes `dl_iterate_phdr()` skip the payload entirely. Anti-tamper SDKs that enumerate loaded libraries via this API will not see it.

**Implementation details:**
- The `soinfo` linked list head is accessible via the `__dl__ZL6solist` symbol in `linker64` (or scan for it)
- On Android 10-14 (API 29-34), the relevant `soinfo` struct fields are:
  - `next` pointer at offset +0x28 (verify per version)
  - `realpath` (char*) or embedded char[] for matching
- You need to read the linked list by following `next` pointers via `/proc/pid/mem`
- When you find the node whose path matches the payload, patch the previous node's `next` to point to the current node's `next`
- Also unlink from the `sonext` global if present

**Create:** `src/soinfo.go` — contains `UnlinkSoinfo(pid int, payloadPath string) error`

**Testing approach:** After unlinking, read `/proc/<child>/maps` and verify the library is still mapped (pages exist) but calling `dl_iterate_phdr` from within the process would not enumerate it. You can verify by checking that the soinfo chain no longer contains the path.

---

### Phase 2: Anonymous Remap (HIGH PRIORITY)

After dlopen and soinfo unlinking, remap the payload's file-backed memory regions as anonymous:

1. **Find all VMAs** belonging to the payload in `/proc/pid/maps` (they'll show the path with `(deleted)`)
2. **For each VMA**, inject a shellcode stub that:
   - `mmap(MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, ...)` over the same address range
   - Copies the page contents (they're already in memory from the original mapping)
   - The kernel replaces the file-backed VMA with an anonymous one

After this, `/proc/self/maps` shows `[anon:linker_alloc]` or blank instead of a file path.

**Implementation details:**
- This requires a "phase 2 shellcode" — a second injection after the initial dlopen
- Reuse the same `/proc/pid/mem` write technique to inject a small stub
- The stub needs to: save regs → mmap(MAP_FIXED) → memcpy → restore regs → signal completion
- Use the same mailbox mechanism for synchronization
- Target the child process (you already have its PID from phase 1)
- You'll need to find a code cave or reuse the same trap address in the child

**Create:** `src/remap.go` — contains `AnonymizePayloadMappings(pid int, payloadPath string) error`

**Important:** The remap must preserve page permissions (r-x for .text, rw- for .data/.bss). Parse the perms from maps before remapping.

---

### Phase 3: Linker Error Buffer Scrub (MEDIUM)

After dlopen, the linker caches the last-loaded library path in internal buffers (`g_ld_debug_verbosity`, dlerror buffer, etc.). Zero these out:

1. Find `__dl__ZL20g_ld_preloads_count` or similar linker globals
2. Zero the `dlerror` thread-local buffer
3. Clear any debug strings that reference the payload path

**Create:** `src/linker_scrub.go`

---

### Phase 4: memfd_create Full Implementation (MEDIUM)

Complete the `BuildMemfdShellcode` path so it's fully functional:

1. Before spawning the child, inject a syscall stub into zygote that calls `memfd_create("jit-cache", MFD_CLOEXEC)` — syscall 279 on arm64
2. Read back the fd number from the stub's return value (via mailbox)
3. Write the entire .so contents into the memfd via `/proc/zygote_pid/mem` at the memfd's backing pages
   - Alternative: use a second shellcode stub that does `write(memfd, buf, len)` in a loop
4. The child inherits the memfd after fork
5. Shellcode calls `dlopen("/proc/self/fd/<N>", RTLD_NOW)`

This gives maps entries like `/memfd:jit-cache (deleted)` which is indistinguishable from legitimate JIT code.

**Update:** `src/shellcode_builder.go` and `src/injector.go`

---

### Phase 5: Timing Hardening (LOW)

- Reduce polling intervals from 100ms/50ms to 10ms/5ms
- Add jitter to avoid timing-based detection patterns
- Consider using `inotify` or `userfaultfd` instead of polling for child detection
- Measure and minimize the total injection window

---

## Code Standards

- All new files go in `src/`
- Module name is `gozinject`
- Target: `GOOS=android GOARCH=arm64 CGO_ENABLED=0`
- Verify compilation with `go build -trimpath -ldflags="-s -w" -o /dev/null ./src/`
- Use the existing logging functions: `LogDebug`, `LogInfo`, `LogWarn`, `LogError`
- ARM64 shellcode must fit in 512 bytes per stage
- All `/proc/pid/mem` operations go through `ReadMem`/`WriteMem` in `memory.go`
- Add new memory primitives to `memory.go` if needed (e.g., `ReadString`, `ReadPointer`)
- Use `encoding/binary` LittleEndian for all pointer reads/writes
- Error handling: return errors up, don't panic. Log warnings for non-fatal issues.

## Build & Verify

```bash
# Compile check (must pass before committing)
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /dev/null ./src/

# Full android build
xmake b injector

# Vet
GOOS=linux GOARCH=arm64 go vet ./src/
```

## Key Android Internals Reference

- `linker64` is at `/system/bin/linker64` (or `/apex/com.android.runtime/bin/linker64` on Android 12+)
- `soinfo` struct: check AOSP `bionic/linker/linker_soinfo.h`
- `__loader_dlopen` is the actual dlopen implementation in linker64
- `memfd_create` = syscall 279 on arm64
- `SYS_openat` = 56, `SYS_unlinkat` = 35, `SYS_close` = 57, `SYS_mmap` = 222
- `AT_FDCWD` = -100
- `RTLD_NOW` = 2
- `MAP_FIXED` = 0x10, `MAP_ANONYMOUS` = 0x20, `MAP_PRIVATE` = 0x02
- `MFD_CLOEXEC` = 0x0001
- `PROT_READ` = 1, `PROT_WRITE` = 2, `PROT_EXEC` = 4
- `prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ...)` can name anonymous mappings to look legitimate

## Commit Strategy

Make one commit per phase. Use descriptive messages:
- `feat(stealth): soinfo unlinking via /proc/pid/mem`
- `feat(stealth): anonymous remap of payload VMAs`
- `feat(stealth): linker error buffer scrub`
- `feat(stealth): memfd_create full implementation`
- `perf(stealth): timing hardening with jitter`

Do NOT push to any remote. This is local-only development.
