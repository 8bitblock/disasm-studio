#pragma once
//
// HvDbg.h
// AMD-V (SVM) hypervisor debugging driver - internal definitions: the VMCB
// layout, per-processor data, MSR/CPUID constants, SVM exit codes, and the
// asm <-> C interface. Structures follow the AMD64 Architecture Programmer's
// Manual Vol. 2 (System Programming), Appendix B (VMCB), and the design is the
// well-understood "subsume the running OS" minimal hypervisor (cf. Satoshi
// Tanda's SimpleSvm, MIT) with an IOCTL control device bolted on.
//
// NOTE: this is built but, per the project decision, NOT loaded - the VMRUN /
// #VMEXIT paths are therefore review-verified, not runtime-verified.
//
#include <ntddk.h>
#include <intrin.h>
#include "../src/Hv/HvDbgProtocol.h"   // shared IOCTL + HVDBG_INFO contract

#define HVDBG_POOL_TAG 'gbDH'   // "HDbg"

// Some WDK header sets export these routines from ntoskrnl.lib but do not
// expose prototypes through ntddk.h. Keep the local declarations narrow.
NTSYSAPI VOID NTAPI RtlCaptureContext(_Out_ PCONTEXT ContextRecord);
NTKERNELAPI VOID KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, _In_opt_ PVOID Context);
NTKERNELAPI VOID KeSignalCallDpcDone(_In_ PVOID SystemArgument1);
NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);

// ----------------------------------------------------------------- MSRs ----
#define MSR_EFER          0xC0000080
#define EFER_SVME         (1ULL << 12)
#define MSR_VM_CR         0xC0010114
#define VM_CR_LOCK        (1ULL << 3)
#define VM_CR_SVMDIS      (1ULL << 4)
#define MSR_VM_HSAVE_PA   0xC0010117
#define MSR_PAT           0x00000277

// ---------------------------------------------------------------- CPUID ----
#define CPUID_FN_VENDOR              0x00000000
#define CPUID_FN_FEATURES            0x00000001   // ECX[31] = hypervisor present
#define CPUID_FN_EXT_FEATURES        0x80000001   // ECX[2]  = SVM
#define CPUID_FN_SVM_FEATURES        0x8000000A   // EDX[0]  = nested paging
#define CPUID_FN1_ECX_HYPERVISOR     (1UL << 31)
#define CPUID_FN8001_ECX_SVM         (1UL << 2)
#define CPUID_FN800A_EDX_NP          (1UL << 0)
// Synthetic leaves serviced by our #VMEXIT(CPUID) handler.
#define CPUID_HVDBG_VENDOR           0x40000000   // returns "HvDbg...." signature
#define CPUID_HVDBG_UNLOAD           0x41414141   // guest VMMCALL/CPUID request to devirtualize

// ----------------------------------------------------- VMCB intercepts -----
#define SVM_INTERCEPT_MISC1_CPUID    (1UL << 18)
#define SVM_INTERCEPT_MISC1_MSR_PROT (1UL << 28)
#define SVM_INTERCEPT_MISC2_VMRUN    (1UL << 0)
#define SVM_INTERCEPT_MISC2_VMMCALL  (1UL << 1)

// ----------------------------------------------- #VMEXIT codes (subset) ----
#define VMEXIT_CPUID      0x072
#define VMEXIT_MSR        0x07C
#define VMEXIT_VMRUN      0x080
#define VMEXIT_VMMCALL    0x081
#define VMEXIT_INVALID    (-1LL)

#define SVM_MSR_VECTOR_SIZE (PAGE_SIZE * 2)   // MSRPM covers three MSR ranges in 2 pages

#pragma warning(push)
#pragma warning(disable : 4201)   // nameless struct/union

// VMCB control area (AMD64 APM Vol.2 App.B, +0x000 .. +0x3FF).
typedef struct _VMCB_CONTROL_AREA {
    USHORT  InterceptCrRead;              // 000
    USHORT  InterceptCrWrite;            // 002
    USHORT  InterceptDrRead;             // 004
    USHORT  InterceptDrWrite;            // 006
    ULONG   InterceptException;          // 008
    ULONG   InterceptMisc1;              // 00c
    ULONG   InterceptMisc2;              // 010
    UCHAR   Reserved1[0x03c - 0x014];    // 014
    USHORT  PauseFilterThreshold;        // 03c
    USHORT  PauseFilterCount;            // 03e
    ULONG64 IopmBasePa;                  // 040
    ULONG64 MsrpmBasePa;                 // 048
    ULONG64 TscOffset;                   // 050
    ULONG   GuestAsid;                   // 058
    UCHAR   TlbControl;                  // 05c
    UCHAR   Reserved2[3];                // 05d
    ULONG64 VIntr;                       // 060
    ULONG64 InterruptShadow;             // 068
    ULONG64 ExitCode;                    // 070
    ULONG64 ExitInfo1;                   // 078
    ULONG64 ExitInfo2;                   // 080
    ULONG64 ExitIntInfo;                 // 088
    ULONG64 NpEnable;                    // 090
    ULONG64 AvicApicBar;                 // 098
    ULONG64 GuestPaOfGhcb;               // 0a0
    ULONG64 EventInj;                    // 0a8
    ULONG64 NCr3;                        // 0b0
    ULONG64 LbrVirtualizationEnable;     // 0b8
    ULONG64 VmcbClean;                   // 0c0
    ULONG64 NRip;                        // 0c8
    UCHAR   NumOfBytesFetched;           // 0d0
    UCHAR   GuestInstructionBytes[15];   // 0d1
    ULONG64 AvicApicBackingPagePointer;  // 0e0
    ULONG64 Reserved3;                   // 0e8
    ULONG64 AvicLogicalTablePointer;     // 0f0
    ULONG64 AvicPhysicalTablePointer;    // 0f8
    ULONG64 Reserved4;                   // 100
    ULONG64 VmcbSaveStatePointer;        // 108
    UCHAR   Reserved5[0x400 - 0x110];    // 110
} VMCB_CONTROL_AREA, *PVMCB_CONTROL_AREA;

// VMCB state-save area (AMD64 APM Vol.2 App.B, offsets relative to +0x400).
typedef struct _VMCB_STATE_SAVE_AREA {
    USHORT  EsSelector;   USHORT EsAttrib;   ULONG EsLimit;   ULONG64 EsBase;   // 000
    USHORT  CsSelector;   USHORT CsAttrib;   ULONG CsLimit;   ULONG64 CsBase;   // 010
    USHORT  SsSelector;   USHORT SsAttrib;   ULONG SsLimit;   ULONG64 SsBase;   // 020
    USHORT  DsSelector;   USHORT DsAttrib;   ULONG DsLimit;   ULONG64 DsBase;   // 030
    USHORT  FsSelector;   USHORT FsAttrib;   ULONG FsLimit;   ULONG64 FsBase;   // 040
    USHORT  GsSelector;   USHORT GsAttrib;   ULONG GsLimit;   ULONG64 GsBase;   // 050
    USHORT  GdtrSelector; USHORT GdtrAttrib; ULONG GdtrLimit; ULONG64 GdtrBase; // 060
    USHORT  LdtrSelector; USHORT LdtrAttrib; ULONG LdtrLimit; ULONG64 LdtrBase; // 070
    USHORT  IdtrSelector; USHORT IdtrAttrib; ULONG IdtrLimit; ULONG64 IdtrBase; // 080
    USHORT  TrSelector;   USHORT TrAttrib;   ULONG TrLimit;   ULONG64 TrBase;   // 090
    UCHAR   Reserved1[0x0cb - 0x0a0];    // 0a0
    UCHAR   Cpl;                         // 0cb
    UCHAR   Reserved2[4];                // 0cc
    ULONG64 Efer;                        // 0d0
    UCHAR   Reserved3[0x148 - 0x0d8];    // 0d8
    ULONG64 Cr4;                         // 148
    ULONG64 Cr3;                         // 150
    ULONG64 Cr0;                         // 158
    ULONG64 Dr7;                         // 160
    ULONG64 Dr6;                         // 168
    ULONG64 Rflags;                      // 170
    ULONG64 Rip;                         // 178
    UCHAR   Reserved4[0x1d8 - 0x180];    // 180
    ULONG64 Rsp;                         // 1d8
    UCHAR   Reserved5[0x1f8 - 0x1e0];    // 1e0
    ULONG64 Rax;                         // 1f8
    ULONG64 Star;                        // 200
    ULONG64 LStar;                       // 208
    ULONG64 CStar;                       // 210
    ULONG64 SfMask;                      // 218
    ULONG64 KernelGsBase;                // 220
    ULONG64 SysenterCs;                  // 228
    ULONG64 SysenterEsp;                 // 230
    ULONG64 SysenterEip;                 // 238
    ULONG64 Cr2;                         // 240
    UCHAR   Reserved6[0x268 - 0x248];    // 248
    ULONG64 GPat;                        // 268
    ULONG64 DbgCtl;                      // 270
    ULONG64 BrFrom;                      // 278
    ULONG64 BrTo;                        // 280
    ULONG64 LastExcepFrom;               // 288
    ULONG64 LastExcepTo;                 // 290
} VMCB_STATE_SAVE_AREA, *PVMCB_STATE_SAVE_AREA;

// A full VMCB is one page: control area + state-save area + reserved tail.
typedef struct _VMCB {
    VMCB_CONTROL_AREA    ControlArea;
    VMCB_STATE_SAVE_AREA StateSaveArea;
    UCHAR Reserved[PAGE_SIZE - sizeof(VMCB_CONTROL_AREA) - sizeof(VMCB_STATE_SAVE_AREA)];
} VMCB, *PVMCB;

// Guest general-purpose registers, in the order PUSHAQ/POPAQ (HvAsm.asm) lays
// them on the stack. RSP here is a dummy slot (the real RSP lives in the VMCB).
typedef struct _GUEST_REGISTERS {
    ULONG64 R15, R14, R13, R12, R11, R10, R9, R8;
    ULONG64 Rdi, Rsi, Rbp, Rsp, Rbx, Rdx, Rcx, Rax;
} GUEST_REGISTERS, *PGUEST_REGISTERS;

// Passed to / from the C #VMEXIT handler each exit.
typedef struct _GUEST_CONTEXT {
    PGUEST_REGISTERS VpRegs;
    BOOLEAN          ExitVm;   // handler sets TRUE to tear the hypervisor down
} GUEST_CONTEXT, *PGUEST_CONTEXT;

// System-wide data shared by every virtual processor (the MSR permission map).
typedef struct _SHARED_VP_DATA {
    PVOID   MsrPermissionsMap;     // 2-page MSRPM
    ULONG64 MsrPermissionsMapPa;
} SHARED_VP_DATA, *PSHARED_VP_DATA;

// Per-logical-processor data. The host stack and the small "layout" at its top
// (read by HvAsm.asm) share storage via the union, exactly as the host RSP is
// pointed at HostStackLayout.GuestVmcbPa before VMRUN.
typedef struct _VIRTUAL_PROCESSOR_DATA {
    union {
        DECLSPEC_ALIGN(PAGE_SIZE) UCHAR HostStackLimit[KERNEL_STACK_SIZE];
        struct {
            UCHAR   StackContents[KERNEL_STACK_SIZE - sizeof(PVOID) * 6];
            ULONG64 GuestVmcbPa;                 // [rsp+00] in HvAsm.asm
            ULONG64 HostVmcbPa;                  // [rsp+08]
            struct _VIRTUAL_PROCESSOR_DATA* Self;// [rsp+10]
            PSHARED_VP_DATA SharedVpData;        // [rsp+18]
            ULONG64 Padding1;                    // [rsp+20] (keep 16-byte alignment)
            ULONG64 Reserved1;                   // [rsp+28]
        } HostStackLayout;
    };
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB  GuestVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB  HostVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) UCHAR HostStateArea[PAGE_SIZE];   // VM_HSAVE_PA target
} VIRTUAL_PROCESSOR_DATA, *PVIRTUAL_PROCESSOR_DATA;

#pragma warning(pop)

// --------------------------------------------------------- asm interface ---
// Defined in HvAsm.asm.
extern void   SvLaunchVm(void* HostRsp);   // enters the guest; returns only on teardown
extern USHORT SvGetCs(void);
extern USHORT SvGetSs(void);
extern USHORT SvGetDs(void);
extern USHORT SvGetEs(void);
extern USHORT SvGetTr(void);
extern USHORT SvGetLdtr(void);
extern void   SvGetGdtr(void* outFword);   // sgdt -> 10-byte pseudo-descriptor (limit:base)
extern void   SvGetIdtr(void* outFword);   // sidt -> 10-byte pseudo-descriptor (limit:base)

// ----------------------------------------------------------- C interface ---
// HvSvm.c
BOOLEAN SvIsSvmSupported(ULONG* flagsOut, char vendorOut[16]);
NTSTATUS SvVirtualizeAllProcessors(void);
VOID     SvDevirtualizeAllProcessors(void);
ULONG    SvVirtualizedCount(void);
ULONG64  SvVmexitCount(void);
extern BOOLEAN SvHandleVmExit(PVIRTUAL_PROCESSOR_DATA VpData, PGUEST_REGISTERS GuestRegisters);
