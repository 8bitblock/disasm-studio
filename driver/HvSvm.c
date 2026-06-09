//
// HvSvm.c
// AMD-V (SVM) virtualization core: capability detection, per-processor VMCB
// preparation, the VMRUN launch (subsuming the running OS as a guest), the
// #VMEXIT handler, and orderly teardown. Driven by HvDbg.c via the IOCTL device.
//
// Design follows the AMD64 APM Vol.2 and the canonical minimal "blue pill"
// pattern. Built but not loaded in this project, so the launch/exit paths are
// review-verified rather than runtime-verified.
//
#include "HvDbg.h"

// --------------------------------------------------------- global state ----
#define HVDBG_MAX_CPUS 256
static PVIRTUAL_PROCESSOR_DATA g_VpData[HVDBG_MAX_CPUS];
static SHARED_VP_DATA          g_Shared;
static volatile LONG           g_VirtualizedCount = 0;
static volatile LONG64         g_VmexitCount      = 0;
static ULONG                   g_CpuCount         = 0;

ULONG   SvVirtualizedCount(void) { return (ULONG)g_VirtualizedCount; }
ULONG64 SvVmexitCount(void)      { return (ULONG64)g_VmexitCount; }

// --------------------------------------------------- capability checks -----
BOOLEAN SvIsSvmSupported(ULONG* flagsOut, char vendorOut[16]) {
    int regs[4];
    ULONG flags = 0;

    // CPU vendor string ("AuthenticAMD") from CPUID leaf 0.
    __cpuid(regs, CPUID_FN_VENDOR);
    if (vendorOut) {
        *(int*)&vendorOut[0]  = regs[1]; // EBX
        *(int*)&vendorOut[4]  = regs[3]; // EDX
        *(int*)&vendorOut[8]  = regs[2]; // ECX
        vendorOut[12] = 0;
    }

    // Hypervisor-present bit: something already owns VMX/SVM (e.g. Hyper-V/HVCI).
    __cpuid(regs, CPUID_FN_FEATURES);
    if ((ULONG)regs[2] & CPUID_FN1_ECX_HYPERVISOR) flags |= HVDBG_FLAG_HV_PRESENT;

    // SVM feature bit (CPUID Fn8000_0001 ECX[2]).
    __cpuid(regs, CPUID_FN_EXT_FEATURES);
    BOOLEAN svm = ((ULONG)regs[2] & CPUID_FN8001_ECX_SVM) != 0;
    if (svm) flags |= HVDBG_FLAG_SVM_SUPPORTED;

    // Nested paging (CPUID Fn8000_000A EDX[0]).
    __cpuid(regs, CPUID_FN_SVM_FEATURES);
    if (svm && ((ULONG)regs[3] & CPUID_FN800A_EDX_NP)) flags |= HVDBG_FLAG_NPT_SUPPORTED;

    // VM_CR.SVMDIS + LOCK => SVM disabled and locked off in firmware.
    ULONG64 vmcr = __readmsr(MSR_VM_CR);
    if ((vmcr & VM_CR_SVMDIS) && (vmcr & VM_CR_LOCK)) flags |= HVDBG_FLAG_SVM_LOCKED_OFF;

    if (flagsOut) *flagsOut = flags;
    return svm && !(flags & HVDBG_FLAG_SVM_LOCKED_OFF);
}

// --------------------------------------------------- segment helpers -------
#pragma pack(push, 1)
typedef union _SEG_DESC {
    ULONG64 value;
    struct {
        USHORT LimitLow;
        USHORT BaseLow;
        UCHAR  BaseMid;
        UCHAR  Attr0;          // type, S, DPL, P
        UCHAR  LimitHighAttr1; // limit[19:16] | AVL,L,DB,G
        UCHAR  BaseHigh;
    } b;
} SEG_DESC;
typedef struct _PSEUDO_DESC { USHORT Limit; ULONG_PTR Base; } PSEUDO_DESC;
#pragma pack(pop)

// SVM 12-bit segment attribute packed from a GDT descriptor (0 for a null sel).
static USHORT SvSegAttr(USHORT selector, ULONG_PTR gdtBase) {
    if ((selector & ~0x7u) == 0) return 0;
    SEG_DESC* d = (SEG_DESC*)(gdtBase + (selector & ~0x7u));
    return (USHORT)(d->b.Attr0 | ((d->b.LimitHighAttr1 & 0xF0) << 4));
}

static void SvFillSeg(USHORT sel, ULONG_PTR gdtBase,
                      USHORT* selOut, USHORT* attrOut, ULONG* limOut) {
    *selOut  = sel;
    *attrOut = SvSegAttr(sel, gdtBase);
    *limOut  = (sel ? __segmentlimit(sel) : 0);
}

// --------------------------------------------------- VMCB preparation ------
static void SvPrepareVmcb(PVIRTUAL_PROCESSOR_DATA vp, CONTEXT* ctx) {
    PVMCB_CONTROL_AREA    ctl  = &vp->GuestVmcb.ControlArea;
    PVMCB_STATE_SAVE_AREA st   = &vp->GuestVmcb.StateSaveArea;

    PSEUDO_DESC gdtr; SvGetGdtr(&gdtr);
    PSEUDO_DESC idtr; SvGetIdtr(&idtr);

    // Intercept CPUID (our control channel) + VMRUN (architecturally required)
    // + MSR access (to shadow EFER.SVME from the guest), and route MSRs through
    // the shared permission map.
    ctl->InterceptMisc1 |= SVM_INTERCEPT_MISC1_CPUID | SVM_INTERCEPT_MISC1_MSR_PROT;
    ctl->InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMRUN;
    ctl->MsrpmBasePa     = g_Shared.MsrPermissionsMapPa;
    ctl->GuestAsid       = 1;

    // Guest visible segment state (CS/SS/DS/ES); FS/GS/TR/LDTR + bases are
    // captured by __svm_vmsave below.
    SvFillSeg(SvGetCs(), gdtr.Base, &st->CsSelector, &st->CsAttrib, &st->CsLimit);
    SvFillSeg(SvGetSs(), gdtr.Base, &st->SsSelector, &st->SsAttrib, &st->SsLimit);
    SvFillSeg(SvGetDs(), gdtr.Base, &st->DsSelector, &st->DsAttrib, &st->DsLimit);
    SvFillSeg(SvGetEs(), gdtr.Base, &st->EsSelector, &st->EsAttrib, &st->EsLimit);

    st->GdtrBase  = gdtr.Base; st->GdtrLimit = gdtr.Limit;
    st->IdtrBase  = idtr.Base; st->IdtrLimit = idtr.Limit;

    st->Efer   = __readmsr(MSR_EFER) | EFER_SVME;
    st->GPat   = __readmsr(MSR_PAT);
    st->Cr0    = __readcr0();
    st->Cr3    = __readcr3();
    st->Cr4    = __readcr4();
    st->Rflags = ctx->EFlags;
    st->Rsp    = ctx->Rsp;
    st->Rip    = ctx->Rip;   // guest resumes exactly where RtlCaptureContext returned
    st->Rax    = ctx->Rax;
}

// --------------------------------------------------- per-CPU virtualize ----
// Returns TRUE once this CPU is running virtualized (the post-VMRUN pass), FALSE
// only on a setup failure.
static BOOLEAN SvIsHvDbgRunning(void) {
    int regs[4];
    __cpuid(regs, CPUID_HVDBG_VENDOR);
    // When virtualized, our CPUID handler writes the "HvDbg" signature into
    // EBX:ECX (regs[1] = "HvDb", low byte of regs[2] = 'g'). Compare from EBX,
    // not EAX (regs[0] holds the max-leaf placeholder), spanning both registers.
    return (BOOLEAN)(memcmp(&regs[1], "HvDbg", 5) == 0);
}

static BOOLEAN SvVirtualizeProcessor(ULONG cpuIndex) {
    PHYSICAL_ADDRESS hi;
    hi.QuadPart = -1;

    PVIRTUAL_PROCESSOR_DATA vp =
        (PVIRTUAL_PROCESSOR_DATA)MmAllocateContiguousMemory(sizeof(VIRTUAL_PROCESSOR_DATA), hi);
    if (!vp) return FALSE;
    RtlZeroMemory(vp, sizeof(*vp));

    CONTEXT* ctx = (CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(CONTEXT), HVDBG_POOL_TAG);
    if (!ctx) { MmFreeContiguousMemory(vp); return FALSE; }

    // Capture the resume point. On the FIRST return we set up and VMRUN; the
    // guest "returns" here a SECOND time, now virtualized, and we report success.
    RtlCaptureContext(ctx);

    if (SvIsHvDbgRunning()) {
        // Second pass: we are the guest now.
        ExFreePoolWithTag(ctx, HVDBG_POOL_TAG);
        g_VpData[cpuIndex] = vp;
        InterlockedIncrement(&g_VirtualizedCount);
        return TRUE;
    }

    // First pass: lay out the host stack the asm loop reads.
    vp->HostStackLayout.GuestVmcbPa  = MmGetPhysicalAddress(&vp->GuestVmcb).QuadPart;
    vp->HostStackLayout.HostVmcbPa   = MmGetPhysicalAddress(&vp->HostVmcb).QuadPart;
    vp->HostStackLayout.Self         = vp;
    vp->HostStackLayout.SharedVpData = &g_Shared;

    SvPrepareVmcb(vp, ctx);
    ExFreePoolWithTag(ctx, HVDBG_POOL_TAG);

    // Enable SVM, point VM_HSAVE_PA at our host save area, snapshot host hidden
    // state into both VMCBs, then launch. SvLaunchVm only returns on teardown.
    __writemsr(MSR_EFER, __readmsr(MSR_EFER) | EFER_SVME);
    __writemsr(MSR_VM_HSAVE_PA, MmGetPhysicalAddress(&vp->HostStateArea).QuadPart);
    __svm_vmsave(vp->HostStackLayout.GuestVmcbPa);
    __svm_vmsave(vp->HostStackLayout.HostVmcbPa);

    SvLaunchVm(&vp->HostStackLayout.GuestVmcbPa);

    // Only reached if VMRUN never engaged (should not happen).
    MmFreeContiguousMemory(vp);
    return FALSE;
}

// --------------------------------------------------- #VMEXIT handler -------
// Called from HvAsm.asm on every #VMEXIT. Returns TRUE to tear the hypervisor
// down for this CPU (and hands the resume context back through GuestRegisters).
BOOLEAN SvHandleVmExit(PVIRTUAL_PROCESSOR_DATA vp, PGUEST_REGISTERS regs) {
    PVMCB_CONTROL_AREA    ctl = &vp->GuestVmcb.ControlArea;
    PVMCB_STATE_SAVE_AREA st  = &vp->GuestVmcb.StateSaveArea;
    InterlockedIncrement64(&g_VmexitCount);

    // Length of the intercepted instruction, used only as a fallback when the
    // CPU did not supply NRip. Stays 0 for exits we don't decode, so we never
    // guess a wrong length (e.g. the 3-byte VMRUN).
    ULONG insnLen = 0;

    switch (ctl->ExitCode) {
    case VMEXIT_CPUID: {
        // The guest's RAX lives in the VMCB save area, NOT in GUEST_REGISTERS:
        // on #VMEXIT the architectural RAX is replaced by the host save-area RAX
        // (the VMCB PA), so regs->Rax is meaningless here. RCX is a normal GPR
        // and is captured correctly by PUSHAQ.
        int leaf = (int)st->Rax, sub = (int)regs->Rcx, out[4];

        if ((ULONG)leaf == CPUID_HVDBG_UNLOAD) {
            // Guest asked us to unload: hand the resume context to the asm
            // teardown (rax=guest RSP, rbx=guest RIP-after-cpuid, rcx=RFLAGS).
            regs->Rax = st->Rsp;
            regs->Rbx = ctl->NRip ? ctl->NRip : st->Rip + 2; // 0F A2 = 2 bytes
            regs->Rcx = st->Rflags;
            return TRUE;
        }

        __cpuidex(out, leaf, sub);
        if ((ULONG)leaf == CPUID_HVDBG_VENDOR) {
            // Advertise our presence so SvIsHvDbgRunning() detects virtualization.
            out[0] = CPUID_HVDBG_UNLOAD; // EAX: max hv leaf placeholder
            memcpy(&out[1], "HvDbg", 5); // EBX/ECX spell the signature
        } else if (leaf == CPUID_FN_FEATURES) {
            out[2] |= (int)CPUID_FN1_ECX_HYPERVISOR; // set hypervisor-present bit
        }
        // RAX result goes back through the VMCB (vmrun reloads guest RAX from
        // st->Rax, so writing regs->Rax would be discarded). RBX/RCX/RDX are
        // plain GPRs: POPAQ restores them and vmrun leaves them untouched.
        st->Rax   = (ULONG)out[0];
        regs->Rbx = (ULONG)out[1];
        regs->Rcx = (ULONG)out[2];
        regs->Rdx = (ULONG)out[3];
        insnLen   = 2;               // CPUID = 0F A2
        break;
    }
    case VMEXIT_MSR:
        // EFER writes: keep SVME set under the hood, reflect the rest. (Minimal.)
        // A full implementation would decode rdmsr/wrmsr from ExitInfo1 here.
        insnLen = 2;                 // RDMSR = 0F 32 / WRMSR = 0F 30
        break;
    default:
        // Unhandled intercept: only NRip can advance us (length unknown). A real
        // build would inject #UD / reflect the event here.
        break;
    }

    // Advance the guest RIP past the intercepted instruction. Prefer the
    // hardware next-RIP; fall back to the known instruction length when NRIPS is
    // unavailable (older or nested CPUs leave NRip == 0). insnLen is 0 for exits
    // we don't decode, so RIP is left untouched rather than guessed wrong.
    // Without this advance the guest re-executes the faulting instruction forever.
    if (ctl->NRip)        st->Rip = ctl->NRip;
    else if (insnLen)     st->Rip += insnLen;
    return FALSE; // keep running the guest
}

// --------------------------------------------------- DPC fan-out -----------
static volatile LONG g_DpcStatus;   // 0 ok, non-zero = a CPU failed

static VOID SvVirtualizeDpc(PKDPC Dpc, PVOID Ctx, PVOID Sys1, PVOID Sys2) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Ctx);
    ULONG idx = KeGetCurrentProcessorNumberEx(NULL);
    if (idx < HVDBG_MAX_CPUS && !g_VpData[idx]) {
        if (!SvVirtualizeProcessor(idx)) InterlockedIncrement(&g_DpcStatus);
    }
    KeSignalCallDpcSynchronize(Sys2);
    KeSignalCallDpcDone(Sys1);
}

static VOID SvDevirtualizeDpc(PKDPC Dpc, PVOID Ctx, PVOID Sys1, PVOID Sys2) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Ctx);
    ULONG idx = KeGetCurrentProcessorNumberEx(NULL);
    if (idx < HVDBG_MAX_CPUS && g_VpData[idx]) {
        int out[4];
        __cpuid(out, CPUID_HVDBG_UNLOAD);          // triggers the teardown path
        __writemsr(MSR_EFER, __readmsr(MSR_EFER) & ~EFER_SVME);
        MmFreeContiguousMemory(g_VpData[idx]);
        g_VpData[idx] = NULL;
        InterlockedDecrement(&g_VirtualizedCount);
    }
    KeSignalCallDpcSynchronize(Sys2);
    KeSignalCallDpcDone(Sys1);
}

// --------------------------------------------------- public entry points ---
NTSTATUS SvVirtualizeAllProcessors(void) {
    ULONG flags = 0; char vendor[16];
    if (!SvIsSvmSupported(&flags, vendor)) return STATUS_HV_FEATURE_UNAVAILABLE;
    if (g_VirtualizedCount != 0) return STATUS_SUCCESS; // already up

    g_CpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    // Shared MSR permission map: 2 contiguous pages, all-zero = pass-through
    // except where we set bits (none here -> EFER handled via the EFER intercept).
    PHYSICAL_ADDRESS hi; hi.QuadPart = -1;
    g_Shared.MsrPermissionsMap = MmAllocateContiguousMemory(SVM_MSR_VECTOR_SIZE, hi);
    if (!g_Shared.MsrPermissionsMap) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_Shared.MsrPermissionsMap, SVM_MSR_VECTOR_SIZE);
    g_Shared.MsrPermissionsMapPa = MmGetPhysicalAddress(g_Shared.MsrPermissionsMap).QuadPart;

    g_DpcStatus = 0;
    KeGenericCallDpc(SvVirtualizeDpc, NULL);   // runs on every logical processor

    if (g_DpcStatus != 0 || g_VirtualizedCount == 0) {
        SvDevirtualizeAllProcessors();
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

VOID SvDevirtualizeAllProcessors(void) {
    if (g_VirtualizedCount > 0)
        KeGenericCallDpc(SvDevirtualizeDpc, NULL);
    if (g_Shared.MsrPermissionsMap) {
        MmFreeContiguousMemory(g_Shared.MsrPermissionsMap);
        g_Shared.MsrPermissionsMap = NULL;
        g_Shared.MsrPermissionsMapPa = 0;
    }
    g_VirtualizedCount = 0;
}
