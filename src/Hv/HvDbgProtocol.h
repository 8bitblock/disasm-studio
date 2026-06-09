#pragma once
//
// HvDbgProtocol.h
// Shared user-mode <-> kernel-mode contract for the AMD-V (SVM) debugging
// backend. The kernel driver (driver/HvDbg.c) creates the \\.\HvDbg device and
// services these IOCTLs; the user-mode client (src/Hv/HvDbgClient.cpp, surfaced
// in the Communications tab) opens the device and drives them.
//
// This header is included by BOTH a C kernel driver and a C++ user-mode client,
// so it pulls in only what each side needs for CTL_CODE and the fixed-width
// Windows integer types, and uses plain C structs with no C++/ntddk specifics.
//
#if defined(_KERNEL_MODE) || defined(_NTDDK_) || defined(_WDMDDK_)
// Kernel side: <ntddk.h>/<wdm.h> (already included by the driver) provide
// CTL_CODE, METHOD_BUFFERED, FILE_ANY_ACCESS, and the ULONG/UCHAR types.
#else
#include <windows.h>
#include <winioctl.h>
#endif

// Device naming. The driver creates \Device\HvDbg + the \DosDevices\HvDbg
// symlink; user mode opens it as \\.\HvDbg via CreateFile.
#define HVDBG_NT_DEVICE_NAME   L"\\Device\\HvDbg"
#define HVDBG_DOS_DEVICE_NAME  L"\\DosDevices\\HvDbg"
#define HVDBG_WIN32_NAME       L"\\\\.\\HvDbg"

// Custom device type (0x8000-0xFFFF is the vendor range) + IOCTL helper.
#define HVDBG_DEVICE_TYPE 0x8000u
#define HVDBG_IOCTL(i)    CTL_CODE(HVDBG_DEVICE_TYPE, 0x800u + (i), METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HVDBG_PING         HVDBG_IOCTL(0) // -> HVDBG_INFO (handshake / capabilities)
#define IOCTL_HVDBG_VIRTUALIZE   HVDBG_IOCTL(1) // enable SVM + VMRUN on every logical CPU
#define IOCTL_HVDBG_DEVIRTUALIZE HVDBG_IOCTL(2) // tear the hypervisor back down
#define IOCTL_HVDBG_GET_STATE    HVDBG_IOCTL(3) // -> HVDBG_INFO (current state, no side effects)

// Identifies a valid HvDbg response and pins the wire layout.
#define HVDBG_PROTOCOL_MAGIC   0x47424456u   // 'VDBG'
#define HVDBG_ABI_VERSION      1u
#define HVDBG_DRIVER_VERSION   0x00010000u   // 1.0

// HVDBG_INFO.flags
#define HVDBG_FLAG_SVM_SUPPORTED      0x0001u // CPUID reports SVM
#define HVDBG_FLAG_NPT_SUPPORTED      0x0002u // SVM nested paging available
#define HVDBG_FLAG_SVM_LOCKED_OFF     0x0004u // VM_CR.SVMDIS set & locked (enable in BIOS)
#define HVDBG_FLAG_HV_PRESENT         0x0008u // CPUID hypervisor-present bit set (something owns VMX/SVM)
#define HVDBG_FLAG_ACTIVE             0x0010u // this driver currently has CPUs virtualized

// Handshake / state payload (METHOD_BUFFERED output for PING and GET_STATE).
#pragma pack(push, 1)
typedef struct _HVDBG_INFO {
    unsigned int       magic;            // HVDBG_PROTOCOL_MAGIC
    unsigned int       abiVersion;       // HVDBG_ABI_VERSION
    unsigned int       driverVersion;    // HVDBG_DRIVER_VERSION
    unsigned int       flags;            // HVDBG_FLAG_*
    unsigned int       cpuCount;         // logical processors on the system
    unsigned int       virtualizedCount; // processors currently running under VMRUN
    unsigned long long vmexitCount;      // total #VMEXIT serviced since virtualize
    char               vendor[16];       // CPU vendor string, e.g. "AuthenticAMD"
} HVDBG_INFO;
#pragma pack(pop)
