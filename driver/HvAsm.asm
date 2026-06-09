;
; HvAsm.asm
; x64 assembly glue for the AMD-V (SVM) hypervisor: the VMRUN host loop and a
; handful of register/segment accessors MSVC has no intrinsic for. Assembled
; with ml64. See HvDbg.h for the C-side declarations and the GUEST_REGISTERS
; layout the PUSHAQ/POPAQ macros mirror.
;
.code

extern SvHandleVmExit : proc

; Push the GPRs in an order that lays them out as GUEST_REGISTERS in memory
; (R15 at the lowest address, RAX at the highest). The RSP slot is a dummy; the
; architectural RSP is carried in the VMCB save area, not here.
PUSHAQ macro
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rax             ; dummy slot for Rsp
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
endm

POPAQ macro
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8          ; discard dummy Rsp slot
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
endm

; void SvLaunchVm(void* HostRsp)
;   HostRsp (rcx) points at VIRTUAL_PROCESSOR_DATA.HostStackLayout.GuestVmcbPa.
;   Layout from that pointer: [+00]=GuestVmcbPa [+08]=HostVmcbPa [+10]=Self ...
SvLaunchVm proc frame
    mov     rsp, rcx
    .endprolog

LaunchLoop:
    mov     rax, qword ptr [rsp]            ; rax = GuestVmcbPa
    vmload  rax                             ; restore guest hidden state from the VMCB
    vmrun   rax                             ; run guest; a #VMEXIT resumes execution here
    vmsave  rax                             ; save guest hidden state back to the VMCB

    ; #VMEXIT does NOT restore the host's hidden segment state (FS/GS/TR/LDTR and
    ; their bases). The C handler below needs the host GS base (KPCR), so reload
    ; the host hidden state from HostVmcbPa ([rsp+8], saved once at setup) before
    ; touching any C code. Without this the handler runs on the guest's GS base.
    mov     rax, qword ptr [rsp + 8]        ; rax = HostVmcbPa
    vmload  rax                             ; restore host hidden state

    PUSHAQ                                  ; capture guest GPRs as GUEST_REGISTERS
    mov     rcx, qword ptr [rsp + 8*16 + 8*2]   ; rcx = Self (PVIRTUAL_PROCESSOR_DATA)
    mov     rdx, rsp                            ; rdx = &GuestRegisters

    sub     rsp, 100h                       ; preserve volatile XMM across the C call
    movaps  xmmword ptr [rsp + 000h], xmm0
    movaps  xmmword ptr [rsp + 010h], xmm1
    movaps  xmmword ptr [rsp + 020h], xmm2
    movaps  xmmword ptr [rsp + 030h], xmm3
    movaps  xmmword ptr [rsp + 040h], xmm4
    movaps  xmmword ptr [rsp + 050h], xmm5
    sub     rsp, 20h                        ; x64 ABI home/shadow space
    call    SvHandleVmExit                  ; BOOLEAN exitVm = SvHandleVmExit(Self, GuestRegisters)
    add     rsp, 20h
    movaps  xmm0, xmmword ptr [rsp + 000h]
    movaps  xmm1, xmmword ptr [rsp + 010h]
    movaps  xmm2, xmmword ptr [rsp + 020h]
    movaps  xmm3, xmmword ptr [rsp + 030h]
    movaps  xmm4, xmmword ptr [rsp + 040h]
    movaps  xmm5, xmmword ptr [rsp + 050h]
    add     rsp, 100h

    test    al, al
    POPAQ                                   ; restore guest GPRs (handler may have edited them)
    jnz     TearDown
    jmp     LaunchLoop

TearDown:
    ; SvHandleVmExit asked to exit. By contract it loaded the resume context into
    ; the GPR image it was handed: rax = guest RSP, rbx = guest RIP, rcx = guest
    ; RFLAGS (copied from the VMCB save area). Resume the now-unvirtualized guest.
    mov     rsp, rax                        ; guest stack
    push    rcx
    popfq                                   ; restore guest RFLAGS
    jmp     rbx                             ; continue at the guest RIP
SvLaunchVm endp

; --- segment / descriptor accessors (no MSVC intrinsics for these) ---
SvGetCs proc
    mov     ax, cs
    ret
SvGetCs endp

SvGetSs proc
    mov     ax, ss
    ret
SvGetSs endp

SvGetDs proc
    mov     ax, ds
    ret
SvGetDs endp

SvGetEs proc
    mov     ax, es
    ret
SvGetEs endp

SvGetTr proc
    str     ax
    ret
SvGetTr endp

SvGetLdtr proc
    sldt    ax
    ret
SvGetLdtr endp

; void SvGetGdtr(void* out) / SvGetIdtr(void* out): store the 10-byte pseudo
; descriptor (limit:base) at [rcx].
SvGetGdtr proc
    sgdt    fword ptr [rcx]
    ret
SvGetGdtr endp

SvGetIdtr proc
    sidt    fword ptr [rcx]
    ret
SvGetIdtr endp

    end
