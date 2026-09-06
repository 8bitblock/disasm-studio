option casemap:none

EXTERN DsGmlOnDispatch:PROC
EXTERN DsGmlOnEntry:PROC
EXTERN DsGmlOnInstanceConstructor:PROC
EXTERN DsGmlOnInstanceDestructor:PROC
EXTERN gDsGmlEnabled:DWORD
EXTERN gDsGmlActiveGates:QWORD
EXTERN gDsGmlXsaveMask:QWORD
EXTERN gDsGmlXsaveBytes:DWORD
EXTERN gDsGmlDispatchContinuation:QWORD
EXTERN gDsGmlEntryContinuation:QWORD
EXTERN gDsGmlInstanceConstructorContinuation:QWORD
EXTERN gDsGmlInstanceDestructorContinuation:QWORD
EXTERN gDsGmlFastControlSequenceAddress:QWORD
EXTERN gDsGmlFastAcceptedSequence:QWORD
EXTERN gDsGmlFastAlwaysSlow:DWORD
EXTERN gDsGmlFastThreads:BYTE
EXTERN gDsGmlBreakpointBloom:BYTE
PUBLIC DsGmlDispatchGate
PUBLIC DsGmlEntryGate
PUBLIC DsGmlInstanceConstructorGate
PUBLIC DsGmlInstanceDestructorGate

.code

; The incoming jump did not push a return address. A synthetic unwind slot
; points at the exact original runner continuation; it is removed by LEA/JMP,
; never RET, so CET's shadow stack remains paired with actual CALL instructions.
DsGmlDispatchGate PROC
    push qword ptr [gDsGmlDispatchContinuation]
    jmp DispatchFastGate
DsGmlDispatchGate ENDP
DsGmlEntryGate PROC
    push qword ptr [gDsGmlEntryContinuation]
    jmp EntrySavedGate
DsGmlEntryGate ENDP
DsGmlInstanceConstructorGate PROC
    push qword ptr [gDsGmlInstanceConstructorContinuation]
    jmp InstanceConstructorSavedGate
DsGmlInstanceConstructorGate ENDP
DsGmlInstanceDestructorGate PROC
    push qword ptr [gDsGmlInstanceDestructorContinuation]
    jmp InstanceDestructorSavedGate
DsGmlInstanceDestructorGate ENDP

; The TEB ClientId.UniqueThread value is at GS:48h in the supported Windows
; x64 ABI. An unclaimed/colliding row takes the checked complete path.
DispatchFastGate PROC FRAME
    pushfq
    .allocstack 8
    push rax
    .allocstack 8
    push r10
    .allocstack 8
    push r11
    .allocstack 8
    .endprolog
    cmp dword ptr [gDsGmlEnabled], 0
    je FastContinue
    mov rax, qword ptr [gDsGmlFastControlSequenceAddress]
    test rax, rax
    jz FastSlow
    mov rax, qword ptr [rax]
    cmp rax, qword ptr [gDsGmlFastAcceptedSequence]
    jne FastSlow
    cmp dword ptr [gDsGmlFastAlwaysSlow], 0
    jne FastSlow
    mov eax, dword ptr gs:[48h]
    mov r10d, eax
    and r10d, 63
    shl r10d, 6
    lea r11, gDsGmlFastThreads
    add r11, r10
    cmp dword ptr [r11], eax
    jne FastSlow
    cmp qword ptr [r11+8], rbx
    jne FastSlow
    mov eax, dword ptr [rbx+94h]
    cmp dword ptr [r11+4], eax
    jne FastSlow
    mov rax, qword ptr [rbx+38h]
    cmp qword ptr [r11+16], rax
    jne FastSlow
    mov rax, qword ptr [rbx+58h]
    cmp qword ptr [r11+24], rax
    jne FastSlow
    inc dword ptr [r11+32]
    test dword ptr [r11+32], 03fffh
    jz FastSlow
    mov r10d, ecx
    shr r10d, 2
    mov eax, dword ptr [r11+44]
    imul eax, eax, -1640531535
    xor eax, r10d
    and eax, 07ffffh
    bt dword ptr [gDsGmlBreakpointBloom], eax
    jc FastSlow
    mov eax, dword ptr [r11+40]
    cmp eax, dword ptr [r11+44]
    je FastContinue
    imul eax, eax, -1640531535
    xor eax, r10d
    and eax, 07ffffh
    bt dword ptr [gDsGmlBreakpointBloom], eax
    jc FastSlow
FastContinue:
    pop r11
    pop r10
    pop rax
    popfq
    lea rsp, [rsp+8]
    mov dword ptr [rbx+09Ch], ecx
    jmp qword ptr [gDsGmlDispatchContinuation]
FastSlow:
    pop r11
    pop r10
    pop rax
    popfq
    jmp DispatchSavedGate
DispatchFastGate ENDP

SaveMachine MACRO
    LOCAL ProbePage, ProbeTail, SaveLegacy, SavedState
    pushfq
    .allocstack 8
    push rax
    .allocstack 8
    push rcx
    .allocstack 8
    push rdx
    .allocstack 8
    push rbx
    .pushreg rbx
    push rbp
    .pushreg rbp
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r8
    .allocstack 8
    push r9
    .allocstack 8
    push r10
    .allocstack 8
    push r11
    .allocstack 8
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    push r15
    .pushreg r15
    mov rbp, rsp
    .setframe rbp, 0
    .endprolog
    lock inc qword ptr [gDsGmlActiveGates]
    mov rcx, rsp
    and rsp, -64
    mov r11d, dword ptr [gDsGmlXsaveBytes]
    add r11, 127
    and r11, -64
ProbePage:
    cmp r11, 4096
    jb ProbeTail
    sub rsp, 4096
    test byte ptr [rsp], 0
    sub r11, 4096
    jmp ProbePage
ProbeTail:
    sub rsp, r11
    test byte ptr [rsp], 0
    cmp qword ptr [gDsGmlXsaveMask], 0
    je SaveLegacy
    ; Standard XSAVE leaves reserved header bytes untouched. XRSTOR requires
    ; them zero, including XCOMP_BV; stack contents are never trusted here.
    xor eax, eax
    mov qword ptr [rsp+576], rax
    mov qword ptr [rsp+584], rax
    mov qword ptr [rsp+592], rax
    mov qword ptr [rsp+600], rax
    mov qword ptr [rsp+608], rax
    mov qword ptr [rsp+616], rax
    mov qword ptr [rsp+624], rax
    mov qword ptr [rsp+632], rax
    mov eax, dword ptr [gDsGmlXsaveMask]
    mov edx, dword ptr [gDsGmlXsaveMask+4]
    xsave64 [rsp+64]
    jmp SavedState
SaveLegacy:
    fxsave64 [rsp+64]
SavedState:
    cld
ENDM

RestoreMachine MACRO
    LOCAL RestoreLegacy, RestoredState
    cmp qword ptr [gDsGmlXsaveMask], 0
    je RestoreLegacy
    mov eax, dword ptr [gDsGmlXsaveMask]
    mov edx, dword ptr [gDsGmlXsaveMask+4]
    xrstor64 [rsp+64]
    jmp RestoredState
RestoreLegacy:
    fxrstor64 [rsp+64]
RestoredState:
    mov rsp, rbp
    lock dec qword ptr [gDsGmlActiveGates]
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq
    lea rsp, [rsp+8]
ENDM

DispatchSavedGate PROC FRAME
    SaveMachine
    cmp dword ptr [gDsGmlEnabled], 0
    je DispatchRestore
    call DsGmlOnDispatch
DispatchRestore:
    RestoreMachine
    ; Exact verified six displaced bytes: 89 8B 9C 00 00 00.
    mov dword ptr [rbx+09Ch], ecx
    jmp qword ptr [gDsGmlDispatchContinuation]
DispatchSavedGate ENDP

EntrySavedGate PROC FRAME
    SaveMachine
    cmp dword ptr [gDsGmlEnabled], 0
    je EntryRestore
    call DsGmlOnEntry
EntryRestore:
    RestoreMachine
    ; Exact verified five displaced bytes: 48 89 54 24 10.
    mov qword ptr [rsp+010h], rdx
    jmp qword ptr [gDsGmlEntryContinuation]
EntrySavedGate ENDP

InstanceConstructorSavedGate PROC FRAME
    SaveMachine
    cmp dword ptr [gDsGmlEnabled], 0
    je ConstructorRestore
    call DsGmlOnInstanceConstructor
ConstructorRestore:
    RestoreMachine
    mov qword ptr [rsp+010h], rbx
    jmp qword ptr [gDsGmlInstanceConstructorContinuation]
InstanceConstructorSavedGate ENDP

InstanceDestructorSavedGate PROC FRAME
    SaveMachine
    cmp dword ptr [gDsGmlEnabled], 0
    je DestructorRestore
    call DsGmlOnInstanceDestructor
DestructorRestore:
    RestoreMachine
    mov qword ptr [rsp+008h], rbx
    jmp qword ptr [gDsGmlInstanceDestructorContinuation]
InstanceDestructorSavedGate ENDP
END
