option casemap:none
EXTERN DsGmlDispatchGate:PROC
EXTERN DsGmlEntryGate:PROC
EXTERN DsGmlInstanceConstructorGate:PROC
EXTERN DsGmlInstanceDestructorGate:PROC
EXTERN TestGateCallback:PROC
EXTERN gGateBefore:BYTE
EXTERN gGateAfter:BYTE
EXTERN gGateOriginalFx:BYTE
EXTERN gGateDummyContext:BYTE
EXTERN gGateEntryWrite:QWORD
EXTERN gGateLifetimeWrites:QWORD
EXTERN gGateMode:DWORD
EXTERN gDsGmlXsaveMask:QWORD
EXTERN gGateXBefore:BYTE
EXTERN gGateXAfter:BYTE
EXTERN gGateXOriginal:BYTE
PUBLIC TestGateFixture
PUBLIC TestDispatchContinuation
PUBLIC TestEntryContinuation
PUBLIC TestConstructorContinuation
PUBLIC TestDestructorContinuation
PUBLIC DsGmlOnDispatch
PUBLIC DsGmlOnEntry
PUBLIC DsGmlOnInstanceConstructor
PUBLIC DsGmlOnInstanceDestructor

SaveX MACRO destination
    LOCAL SkipX
    pushfq
    cmp qword ptr [gDsGmlXsaveMask],0
    je SkipX
    push rax
    push rdx
    mov eax,dword ptr [gDsGmlXsaveMask]
    mov edx,dword ptr [gDsGmlXsaveMask+4]
    xsave64 [destination]
    pop rdx
    pop rax
SkipX:
    popfq
ENDM
Capture MACRO destination, extended
    mov qword ptr [destination+0], r15
    mov qword ptr [destination+8], r14
    mov qword ptr [destination+16], r13
    mov qword ptr [destination+24], r12
    mov qword ptr [destination+32], r11
    mov qword ptr [destination+40], r10
    mov qword ptr [destination+48], r9
    mov qword ptr [destination+56], r8
    mov qword ptr [destination+64], rdi
    mov qword ptr [destination+72], rsi
    mov qword ptr [destination+80], rbp
    mov qword ptr [destination+88], rbx
    mov qword ptr [destination+96], rdx
    mov qword ptr [destination+104], rcx
    mov qword ptr [destination+112], rax
    pushfq
    pop qword ptr [destination+120]
    fxsave64 [destination+128]
    SaveX extended
ENDM
.code
TestGateFixture PROC FRAME
    push rbx
    .pushreg rbx
    push rbp
    .pushreg rbp
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    sub rsp, 40
    .allocstack 40
    .endprolog
    mov gGateMode, ecx
    fxsave64 [gGateOriginalFx]
    SaveX gGateXOriginal
    pcmpeqd xmm0, xmm0
    movdqa xmm1, xmm0
    movdqa xmm2, xmm0
    movdqa xmm3, xmm0
    movdqa xmm4, xmm0
    movdqa xmm5, xmm0
    movdqa xmm6, xmm0
    movdqa xmm7, xmm0
    movdqa xmm8, xmm0
    movdqa xmm9, xmm0
    movdqa xmm10, xmm0
    movdqa xmm11, xmm0
    movdqa xmm12, xmm0
    movdqa xmm13, xmm0
    movdqa xmm14, xmm0
    movdqa xmm15, xmm0
    test qword ptr [gDsGmlXsaveMask],4
    jz InitializedSimd
    vpcmpeqd ymm0,ymm0,ymm0
    test qword ptr [gDsGmlXsaveMask],080h
    jz InitializedSimd
    vpternlogd zmm31,zmm31,zmm31,0ffh
    kxnorw k1,k1,k1
InitializedSimd:
    mov rax, 01111111111111111h
    mov rcx, 02468h
    mov rdx, 03333333333333333h
    lea rbx, gGateDummyContext
    mov rbp, 05555555555555555h
    mov rsi, 06666666666666666h
    mov rdi, 07777777777777777h
    mov r8, 08888888888888888h
    mov r9, 09999999999999999h
    mov r10, 0AAAAAAAAAAAAAAAAh
    mov r11, 0BBBBBBBBBBBBBBBBh
    mov r12, 0CCCCCCCCCCCCCCCCh
    mov r13, 0DDDDDDDDDDDDDDDDh
    mov r14, 0EEEEEEEEEEEEEEEEh
    mov r15, 0FFFFFFFFFFFFFFFFh
    cmp gGateMode, 0
    jne EnterFixture
    push 0E97h
    popfq
    Capture gGateBefore, gGateXBefore
    jmp DsGmlDispatchGate
EnterFixture:
    cmp gGateMode, 1
    jne ConstructorFixture
    push 0E97h
    popfq
    Capture gGateBefore, gGateXBefore
    jmp DsGmlEntryGate
ConstructorFixture:
    cmp gGateMode, 2
    jne DestructorFixture
    push 0E97h
    popfq
    Capture gGateBefore, gGateXBefore
    jmp DsGmlInstanceConstructorGate
DestructorFixture:
    push 0E97h
    popfq
    Capture gGateBefore, gGateXBefore
    jmp DsGmlInstanceDestructorGate
TestDispatchContinuation LABEL NEAR
    Capture gGateAfter, gGateXAfter
    jmp FinishFixture
TestEntryContinuation LABEL NEAR
    Capture gGateAfter, gGateXAfter
    mov rax, [rsp+10h]
    mov gGateEntryWrite, rax
    jmp FinishFixture
TestConstructorContinuation LABEL NEAR
    Capture gGateAfter, gGateXAfter
    mov rax, [rsp+10h]
    mov gGateLifetimeWrites, rax
    jmp FinishFixture
TestDestructorContinuation LABEL NEAR
    Capture gGateAfter, gGateXAfter
    mov rax, [rsp+8]
    mov qword ptr [gGateLifetimeWrites+8], rax
FinishFixture:
    cld
    cmp qword ptr [gDsGmlXsaveMask],0
    je RestoreFixtureLegacy
    mov eax,dword ptr [gDsGmlXsaveMask]
    mov edx,dword ptr [gDsGmlXsaveMask+4]
    xrstor64 [gGateXOriginal]
RestoreFixtureLegacy:
    fxrstor64 [gGateOriginalFx]
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
TestGateFixture ENDP

DsGmlOnDispatch PROC FRAME
    sub rsp, 40
    .allocstack 40
    .endprolog
    call TestGateCallback
    test qword ptr [gDsGmlXsaveMask],4
    jz ClobberLegacy
    vzeroupper
    test qword ptr [gDsGmlXsaveMask],080h
    jz ClobberLegacy
    vpxord zmm31,zmm31,zmm31
    kxorw k1,k1,k1
ClobberLegacy:
    pxor xmm0, xmm0
    pxor xmm1, xmm1
    pxor xmm2, xmm2
    pxor xmm3, xmm3
    pxor xmm4, xmm4
    pxor xmm5, xmm5
    xor eax, eax
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    add rsp, 40
    ret
DsGmlOnDispatch ENDP
DsGmlOnEntry PROC
    jmp DsGmlOnDispatch
DsGmlOnEntry ENDP
DsGmlOnInstanceConstructor PROC
    jmp DsGmlOnDispatch
DsGmlOnInstanceConstructor ENDP
DsGmlOnInstanceDestructor PROC
    jmp DsGmlOnDispatch
DsGmlOnInstanceDestructor ENDP
END
