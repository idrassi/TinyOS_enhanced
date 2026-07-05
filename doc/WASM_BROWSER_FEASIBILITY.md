# Feasibility Study: Running TinyOS in the Browser via WebAssembly

**Date:** 2026-07-05
**Verdict: Feasible — empirically confirmed.** The unmodified `dist/tinyos.iso`
boots in v86 (headless, Node) all the way to the interactive first-boot password
prompt. Route: run the v86 emulator (x86→WASM JIT) in the browser and boot the
existing ISO; **not** by compiling the kernel to WASM directly.

---

## 0. Empirical result (2026-07-05)

Booted `dist/tinyos.iso` in v86 v0.x (npm `v86`, prebuilt `v86.wasm`) headless
under Node v22, SeaBIOS + VGABIOS ROMs, 256 MB, CD-ROM boot. Captured serial +
VGA text. Two tests were run:

**Test A — boot to prompt.** Clean boot to the first-boot "Enter new root
password:" prompt, no panics, no faults.

**Test B — full interactive signed-exec chain (the definitive result).** Drove
the whole flow via scripted keystrokes (`keyboard_send_text`): first-boot
password setup (PBKDF2 100k) → root login → shell → `exec /hello.elf` under
**default ENFORCE signing** (no permissive flag). Result, all from serial:

```
[ELF] Found signature (offset=13104, elf_size=13104)
[ELF] Hash verification: PASS
[ELF] Signature verification: PASS
[ELF]  Binary 'hello.elf' has valid ECDSA signature
...
Hello from ELF!          <- ring-3 syscall output
ELF program exiting.
[SYSCALL] Process exited with status 0
[EXEC] Process completed
```

**The complete ECDSA P-256 + SHA-256 signed-exec path passed under v86's JIT —
hash PASS, signature PASS, ring-3 execution, clean exit(0), process reaped,
user PDPT/page-tables freed, zero triple faults.** This is the exact chain that
historically triple-faulted on real QEMU before the 2026 fixes; it runs
correctly in the browser emulator. Test B was CD-only (no HDD image), so FAT32
C: is unavailable (`[IDE] ERROR: IDE not initialized` — expected, benign); D:
(RAMFS) works.

Key findings, several of which *overturn* the pre-test predictions below in
TinyOS's favor:

| Predicted (§4) | Actual in v86 | Evidence (serial) |
|---|---|---|
| PAE likely absent → untested fallback path | **PAE fully supported.** Real PAE path runs: CR4.PAE enabled, PDPT at 0x1f1000, 256 MB identity-mapped, "verified complete (no holes)" | `[PAE] CPU supports PAE [OK]` … `[PAE] PAE enabled in CR4 [OK]` |
| RDRAND/RDSEED absent → weak entropy | **RDRAND supported and healthy.** | `[ENTROPY] RDRAND health check [PASS]` / `Quality: STRONG` |
| FXSR hard requirement | Satisfied, no panic | Boot proceeds past kernel.c:179-198 |
| NX optional | **NX unavailable** → graceful "W^X PARTIAL" | `[PAE] NX bit support [UNAVAILABLE]` / `W^X enforcement: PARTIAL` |

Net effect: **Gap 2 (non-PAE fallback risk) is eliminated** — v86 exercises the
real PAE code path, so the hardened PAE logic (COW page tables, user PDPT, guard
pages) is what actually runs. The only degradation observed is NX (W^X becomes
partial), which is expected and non-fatal. GRUB2 El Torito CD boot under v86's
SeaBIOS **works** (the previously-open mechanical question).

Not yet exercised: completing the password flow, `exec /hello.elf` under
ENFORCE signing (speed-dependent), FAT32 C: (no IDE disk image attached in this
test — CD-only boot), and e1000 networking (still absent in v86; see Gap 1).

---

## 1. Scope and approach

Question: can TinyOS (32-bit i386 Multiboot2 kernel, ring-3 user processes,
PAE/W^X, signed exec) run completely inside a modern browser as WebAssembly?

Two routes were evaluated:

1. **Compile the kernel itself to WASM** — infeasible. The kernel is
   inseparable from ring transitions, hardware page tables, port I/O, and real
   IDT/GDT/TSS semantics; none of these exist in the WASM machine model. This
   would be a rewrite, not a port.
2. **Run an x86 PC emulator (itself WASM/JIT-to-WASM) in the browser and boot
   the existing ISO unmodified** — feasible. This study covers route 2.

Inputs: a source-level inventory of TinyOS's hardware/CPU dependencies, and a
survey of browser-based x86 emulators as of mid-2026.

---

## 2. TinyOS hardware/CPU dependency inventory

### 2.1 Hard requirements

| Dependency | Detail | Reference |
|---|---|---|
| **FXSR** | `kernel_panic("CPU lacks FXSR support")` if CPUID.1:EDX[24] absent; context switch uses FXSAVE/FXRSTOR unconditionally (no FSAVE fallback, deliberately removed) | kernel.c:179-198, context_switch.S:145-232 |
| **Multiboot2 loader** | Magic 0xE85250D6, validates EAX=0x36D76289 at entry; needs GRUB2, won't boot as raw MBR or Multiboot1 | boot.s:14, kernel.c:280 |
| **Legacy IDE/ATA PIO, primary channel** | FAT32 C: rides directly on ports 0x1F0 family, PIO polling, no DMA/AHCI/virtio | ide.c, fat32.c |
| **8259 PIC (remapped), 8254 PIT @ 100 Hz** | No APIC, no I/O APIC, no HPET, no TSC-deadline anywhere | pic.c, pit.c:69-127, kernel.c:433 |
| **i8042 PS/2 keyboard** | Ports 0x60/0x64, IRQ1; no USB HID | keyboard.c |
| **VGA text mode @ 0xB8000** | 80x25, CRTC cursor via 0x3D4/0x3D5; no framebuffer/VBE (Multiboot2 header requests no framebuffer tag) | vga.c, boot.s |
| **16550 UART COM1 (0x3F8)** | Serial logging | serial.c |
| **CMOS RTC (0x70/0x71)** | | time.c:14-19 |
| **PCI config mechanism #1 (0xCF8/0xCFC)** | | pci.c:15-16 |
| **≥32 MB RAM** | Early identity map covers 32 MB; actual map read from Multiboot2 info; docs run with 256 MB but no hard dependency on that figure | kernel.c:354, pmm.c:52 |

### 2.2 Graceful degradation (optional features)

| Feature | Behavior when absent | Reference |
|---|---|---|
| **PAE** | `pae_init()` CPUID-checks; falls back to legacy 32-bit paging + 32 MB early identity map without panic. W^X/NX protection lost; boot continues. W^X verify panic is gated on `pae_is_active()` | pae.c:272,444; kernel.c:352-363,384 |
| **NX** | `pae_enable_nx()` checks CPUID 0x80000001:EDX[20]; returns false gracefully. EFER MSR (0xC0000080) written only when NX present — the only MSR in the build | pae.c:297-337 |
| **RDRAND/RDSEED** | CPUID-gated in both entropy.c and crypto.c; falls back to TSC-jitter/PIT/address entropy. No fault. Entropy quality on a deterministic emulator is weak (security caveat, not a crash) | entropy.c:63-130, crypto.c:876-1078 |
| **SSE** | Detected; CR4.OSXMMEXCPT set only if present. FXSR is the actual gate | kernel.c:200-207 |
| **Networking (e1000)** | PCI scan matches exactly vendor 0x8086 / device 0x100E (82540EM), MMIO + bus-master DMA. **Not boot-mandatory**: DHCP times out after 30 s to APIPA 169.254.x.x and boot proceeds. No other NIC driver exists | pci.c:18-19,217; e1000.c; kernel.c:530-590 |
| **FAT32 mount** | Failure is non-fatal (warn, C: unavailable). D: is RAMFS (no hardware) | kernel.c:701 |

### 2.3 Non-issues

- **SMP:** single-CPU throughout (cli/sti critical sections, no MP tables, no SIPI).
- **Secure boot / TPM:** pure software (in-kernel SHA-512 PCR emulation); no TPM MMIO, no UEFI.
- **QEMU-specifics:** none — no fw_cfg, no debug ports, no virtio. `-cpu Broadwell,+rdrand,+rdseed` in the docs is a convenience, not a requirement.
- Target profile: a clean legacy i440FX-class PC.

---

## 3. Browser-based x86 emulator survey (mid-2026)

| Option | Fit for TinyOS |
|---|---|
| **v86** (github.com/copy/v86, BSD, actively maintained) | **Best fit — confirmed booting (§0).** i386-only x86→WASM JIT. Pentium-4-level CPU incl. SSE3 (FXSR satisfied). IDE/ATA, ISO-9660 CD, PS/2, VGA text, PIT/PIC, COM1, RTC, PCI all present. NICs: NE2000 + virtio-net (**no e1000**). **PAE present and RDRAND present** (both empirically verified — docs had understated this). NX absent. ~10x below native. |
| **Halfix** (github.com/nepx/halfix) | Only browser emulator that names **PAE** support (P4/Core-Duo class, SSE2). But **cannot boot ISOs** (broken ATAPI — HDD images only) and is less maintained. |
| **qemu-wasm** (github.com/ktock/qemu-wasm) | Experimental (FOSDEM 2025). Targets x86_64/aarch64/riscv64 — **no i386 system emulation demoed**. Requires SharedArrayBuffer/COOP-COEP; TCG-wasm backend not merged upstream. |
| **CheerpX / WebVM, Boxedwine** | Userspace-only syscall emulation (Linux/Win32 binaries). **Cannot boot a kernel.** Ruled out. |

Browser networking (all options): no raw sockets in browsers, so guest ethernet
egresses via a WebSocket VLAN proxy (v86 WSProxy / websockproxy), the WISP
protocol (TCP/UDP over WebSocket), or v86's fetch() backend (guest HTTP →
browser fetch; v86 handles DHCP/ARP internally). Proxy-free options are limited
to same-browser VLANs (BroadcastChannel) or HTTP-only.

---

## 4. Gap analysis: TinyOS on v86

Cross-referencing sections 2 and 3, every hard requirement is met. Three gaps
remain, none blocking an offline demo:

### Gap 1 — No e1000 NIC (only hard device mismatch)
v86 offers NE2000 and virtio-net; TinyOS binds only 8086:100E. Since networking
is not boot-mandatory, the OS runs fine offline (APIPA fallback). To get
networking:
- **Write an ne2k driver** — the pragmatic choice: PIO-based, no DMA descriptor
  rings, a few hundred lines; or
- write a virtio-net driver (more code, better performance); or
- contribute e1000 emulation to v86 (Rust, nontrivial).

### Gap 2 — PAE ~~almost certainly absent~~ **RESOLVED: PAE present in v86**
Pre-test this was the top risk. The §0 boot test disproves it: **v86 supports
PAE**, so TinyOS runs its real, hardened PAE path (CR4.PAE, 256 MB identity map
verified hole-free), not the legacy fallback. Only NX is missing → W^X degrades
to "PARTIAL" gracefully, as designed. No pre-flight PAE-masking test needed.

### Gap 3 — ~~No RDRAND~~ + emulation speed
- **RDRAND is present in v86** (§0: health check PASS, "Quality: STRONG"), so
  the weak-entropy concern does not apply on this emulator. (Note: v86's RDRAND
  is still emulator-generated, not true hardware entropy — fine for a demo.)
- Speed remains the real practical issue. v86 is ~an order of magnitude below
  native, and PBKDF2-100k first-boot
  password setup plus bit-serial ECDSA exec verification are already
  minutes-scale under QEMU/TCG. For a browser demo build:
  - compile with `-DTINYOS_FAST_KDF` (explicit, documented opt-out), and
  - decide whether to keep ENFORCE signing (works, slowly) or ship the demo
    with `-DELF_PERMISSIVE_SIGNATURES`.

### Open mechanical question
GRUB2 El Torito CD boot under v86's SeaBIOS is undocumented-but-plausible
(routinely done with Linux ISOs). A 10-minute local test of `dist/tinyos.iso`
in v86 settles it; do this first.

---

## 5. What the port amounts to

A static web page embedding v86, the **unmodified** `tinyos.iso` as the CD
image, VGA canvas + serial console div. No kernel changes strictly required for
an offline demo. Natural fit as a "boot TinyOS in your browser" live-demo link
on the GitHub repo.

**Recommended order:**
1. ~~Test the current ISO in v86 locally as-is~~ **DONE (§0, Test A)** — boots
   clean; El Torito + PAE + RDRAND all confirmed working.
2. ~~Smoke-test the non-PAE path~~ **N/A** — v86 runs the real PAE path.
3. ~~Drive the full interactive flow (password → login → `exec` under
   ENFORCE)~~ **DONE (§0, Test B)** — signed exec passes end-to-end, `Hello
   from ELF!`, exit(0), zero triple faults. Crypto is slow-but-correct under
   the JIT; a demo build may still want `-DTINYOS_FAST_KDF` purely for
   password-setup latency, but signing works as-is and need not be disabled.
4. Attach a FAT32 disk image as an IDE drive and confirm C: mounts (both §0
   tests were CD-only; C: not yet exercised — D:/RAMFS works).
5. Wrap in a static web page (v86 + ISO + VGA canvas + serial div).
6. *(Optional)* Add an ne2k driver + WISP/fetch proxy for networking.

Steps 4–5 are days, not weeks. The NIC driver (step 6) is the only open-ended
piece. **The core feasibility question is now answered empirically: yes.**

---

## 6. Sources

- https://github.com/copy/v86 · https://github.com/copy/v86/blob/master/docs/networking.md
- https://github.com/nepx/halfix · https://github.com/nepx/halfix/blob/master/compatibility.md
- https://github.com/ktock/qemu-wasm · https://archive.fosdem.org/2025/schedule/event/fosdem-2025-6290-running-qemu-inside-browser/
- https://github.com/leaningtech/webvm · https://cheerpx.io/
- TinyOS source: kernel.c, boot.s, pae.c, pci.c, e1000.c, ide.c, fat32.c,
  pit.c, pic.c, keyboard.c, vga.c, serial.c, time.c, entropy.c, crypto.c,
  context_switch.S (all under `src/`)
