## 11. Hypervisor (AMD-V/SVM) Backend & Kernel Driver

DisasmStudio ships, alongside its user-mode application, an **experimental hardware-assisted debugging backend** built on **AMD-V (SVM — Secure Virtual Machine)**. The idea is research-grade and entirely optional: where the standard Win32 debugger (Chapter 6) controls a target through the documented OS debug API — which writes `int3` (`0xCC`) breakpoint bytes into the target and is therefore observable by the target itself — a thin hypervisor can in principle observe and control execution from *underneath* the operating system, leaving a much smaller footprint inside the guest. This chapter documents the **structure and purpose** of that subsystem. It is deliberately high-level: per the project spec, **packaging, signing, loading, and runtime validation of the kernel driver are outside the normal application target**, and the entire main application builds, runs, and delivers every feature in this document *without* the driver present.

### Role within the project

The hypervisor backend is a **secondary, opt-in control path** for the debugger, not a replacement for it. Nothing in the static-analysis pipeline (loaders, disassembly, decompiler, function naming, tech-scan, persistence) depends on it, and nothing in the live Win32 debugger requires it. It exists as a forward-looking research avenue: a way to experiment with low-artifact, hardware-assisted introspection of a running system. The Communications tab (Chapter 8) is where the application surfaces a client channel to the driver when one is installed; everywhere else the subsystem is dormant.

### Two halves: user-mode client and kernel-mode driver

The code is split cleanly across the user/kernel boundary, with a single shared ABI header defining the contract between them.

#### User-mode side — `src/Hv/`

- **`HvDbgProtocol.h`** — the **shared ABI**: the device name, the set of control codes (IOCTLs), and the request/response structures that the user-mode client and the kernel driver agree on. Keeping this contract in one header is what lets both sides be compiled independently yet stay byte-compatible. It is the single source of truth for "what messages can be exchanged."
- **`HvDbgClient.{h,cpp}`** — the **user-mode client**. It opens a handle to the driver's device object (a `\\.\`-style device path), marshals requests into the protocol structures, issues the control calls, and unmarshals the replies into types the rest of the application can use. It is written to **degrade gracefully**: if the driver is not installed or not reachable, the client simply reports "unavailable" and the application carries on with the ordinary Win32 debugger.
- **`HvDbgLoader.{h,cpp}`** — a **service/driver lifecycle helper** that wraps the Windows Service Control Manager to register, start, stop, and remove the kernel-mode service that hosts the driver. This is the bridge between "a `.sys` file on disk" and "a loaded, talkable device," and it is the piece most affected by the out-of-scope caveat below (loading an unsigned kernel driver requires a specially-configured machine).
- **`load-driver.ps1`** (repo root) — a developer convenience script for the install/load step during experimentation.

#### Kernel-mode side — `driver/`

The `driver/` directory contains the kernel component as a separate build target (it is *not* part of `DisasmStudio.sln`'s normal app build):

- **`HvDbg.h`** — shared kernel-side definitions (device/IOCTL declarations and internal structures) — the kernel counterpart to the user-mode protocol header.
- **`HvDbg.c`** — the **driver entry point and device surface**: it creates the device object the user-mode client connects to, registers the dispatch routines, and routes incoming control requests to the appropriate handler. This is the driver's "front door."
- **`HvSvm.c`** — the **SVM core**: the logic that checks for processor virtualization support, prepares the control structures the CPU's virtualization extensions require, and enters/leaves the hypervisor context. This is where the AMD-V-specific machinery lives.
- **`HvAsm.asm`** — the small amount of **hand-written assembly glue** that cannot be expressed in C: the low-level entry/exit sequence and register save/restore around the hardware virtualization transitions. Mixing a focused `.asm` translation unit with the C core is standard practice for this class of code, because the transition sequence must control exact register state.

### Why hardware-assisted, and what it buys

The motivation is **fidelity and stealth for analysis**: a target that actively resists debugging can detect software breakpoints, single-step flags, and the presence of the OS debug API. A hypervisor-based observer can, in principle, intercept events without modifying the target's code bytes and without the in-process artifacts the OS debugger leaves behind. For a reverse-engineering workbench whose whole purpose is to understand uncooperative software, this is a natural — if advanced — capability to explore. It is presented here as a **defensive/analysis research feature**, consistent with the rest of the tool's purpose (understanding binaries, not deploying them).

### Boundaries and reality

It is important to be precise about what is and is not delivered:

- The **user-mode client, loader, and protocol** are present and compile as part of the source tree.
- The **kernel driver sources** are present under `driver/` as a separate target.
- **Building, signing, loading, and validating** the driver at runtime is **explicitly out of scope** for the normal product. Loading an unsigned kernel driver on modern Windows requires test-signing mode (or a properly signed driver) and Driver Signature Enforcement considerations — environment configuration the application neither performs nor depends on.
- Consequently, the hypervisor path should be regarded as **experimental and machine-dependent** (it requires an AMD processor with SVM available and enabled, and a host configured to load the driver). The shipped, supported experience is the user-mode workbench plus the Win32 debugger.

#### Limitations & notes

- **Optional and dormant by default.** No documented feature requires the driver; with it absent, the client reports unavailable and the app uses the standard debugger.
- **Hardware- and host-specific.** Requires AMD-V/SVM-capable hardware and a host configured to load a custom kernel driver; not portable to Intel VT-x as written.
- **Out-of-scope operationalization.** Driver packaging, signing, loading, and runtime validation are intentionally not part of the app target, per the project spec — so this chapter documents architecture and intent rather than an end-to-end, turnkey capability.
- **Research framing.** The backend exists to explore low-artifact, hardware-assisted introspection for *analysis* of uncooperative binaries; it is described here at the level of structure and purpose, not as an operational evasion guide.
- **Single source of truth for the ABI.** Any change to the exchanged messages must be made in the shared protocol header so the user-mode and kernel-mode halves stay compatible.
