//
// HvDbg.c
// AMD-V (SVM) hypervisor debugging driver - WDM glue: the control device,
// the user-mode IOCTL protocol (HvDbgProtocol.h), and the create/close/unload
// plumbing that ties the user-mode client to the SVM core (HvSvm.c).
//
// Classic WDM driver (no KMDF): one buffered-I/O control device, \Device\HvDbg
// + the \DosDevices\HvDbg symlink, FILE_DEVICE_SECURE_OPEN. The IOCTL handlers
// are thin - capability reporting plus virtualize / devirtualize - and defer all
// the SVM work to the SvXxx() entry points.
//
// Built but, per the project decision, NOT loaded; the device/IOCTL paths are
// straightforward and review-verified.
//
#include "HvDbg.h"
#include <initguid.h>   // instantiate the GUID below (must precede the DEFINE_GUID)
#include <wdmsec.h>     // IoCreateDeviceSecure + SDDL_* (link wdmsec.lib)

// Device class GUID required by IoCreateDeviceSecure. Arbitrary but stable; it
// only namespaces this control device's security registry key.
// {6B2A1F4C-9C3E-4D7A-B1E2-3F5A6C8D9E0F}
DEFINE_GUID(GUID_DEVCLASS_HVDBG,
    0x6b2a1f4c, 0x9c3e, 0x4d7a, 0xb1, 0xe2, 0x3f, 0x5a, 0x6c, 0x8d, 0x9e, 0x0f);

// --------------------------------------------------- forward declarations ---
DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD HvDbgUnload;
static DRIVER_DISPATCH HvDbgCreateClose;
static DRIVER_DISPATCH HvDbgDeviceControl;

// Cached symlink name (constant), used by both DriverEntry and unload.
static UNICODE_STRING g_DosDeviceName = RTL_CONSTANT_STRING(HVDBG_DOS_DEVICE_NAME);

// --------------------------------------------------- HVDBG_INFO helper ------
// Fill a caller-provided HVDBG_INFO with the current capability + runtime state.
// Caller is responsible for having validated/zeroed the buffer.
static VOID HvDbgFillInfo(HVDBG_INFO* info) {
    ULONG flags = 0;
    char  vendor[16] = { 0 };

    // SvIsSvmSupported reports the SVM_SUPPORTED / NPT_SUPPORTED / HV_PRESENT /
    // SVM_LOCKED_OFF capability bits and the CPU vendor string in one shot.
    (VOID)SvIsSvmSupported(&flags, vendor);
    if (SvVirtualizedCount() > 0) flags |= HVDBG_FLAG_ACTIVE;

    info->magic            = HVDBG_PROTOCOL_MAGIC;
    info->abiVersion       = HVDBG_ABI_VERSION;
    info->driverVersion    = HVDBG_DRIVER_VERSION;
    info->flags            = flags;
    info->cpuCount         = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    info->virtualizedCount = SvVirtualizedCount();
    info->vmexitCount      = SvVmexitCount();
    RtlCopyMemory(info->vendor, vendor, sizeof(info->vendor));
}

// --------------------------------------------------- IRP_MJ_CREATE/CLOSE ----
static NTSTATUS HvDbgCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// --------------------------------------------------- IRP_MJ_DEVICE_CONTROL --
static NTSTATUS HvDbgDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS  status  = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info    = 0;
    ULONG     code    = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG     outLen  = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (code) {
    case IOCTL_HVDBG_PING:
    case IOCTL_HVDBG_GET_STATE: {
        // Both return a fully-populated HVDBG_INFO (METHOD_BUFFERED, so the
        // system buffer is the output buffer). PING and GET_STATE are identical
        // on the wire; neither has side effects.
        if (outLen < sizeof(HVDBG_INFO)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        HVDBG_INFO* out = (HVDBG_INFO*)Irp->AssociatedIrp.SystemBuffer;
        RtlZeroMemory(out, sizeof(HVDBG_INFO));   // no info leak
        HvDbgFillInfo(out);
        info   = sizeof(HVDBG_INFO);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_HVDBG_VIRTUALIZE:
        // Enable SVM + VMRUN on every logical CPU. SvVirtualizeAllProcessors
        // already returns mapped NTSTATUS values.
        status = SvVirtualizeAllProcessors();
        break;

    case IOCTL_HVDBG_DEVIRTUALIZE:
        // Tear the hypervisor back down (idempotent - safe when not running).
        SvDevirtualizeAllProcessors();
        status = STATUS_SUCCESS;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// --------------------------------------------------- DriverUnload -----------
static VOID HvDbgUnload(PDRIVER_OBJECT DriverObject) {
    // Make sure no CPU is left virtualized before the code pages go away.
    SvDevirtualizeAllProcessors();

    IoDeleteSymbolicLink(&g_DosDeviceName);
    if (DriverObject->DeviceObject)
        IoDeleteDevice(DriverObject->DeviceObject);
}

// --------------------------------------------------- DriverEntry ------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING ntDeviceName = RTL_CONSTANT_STRING(HVDBG_NT_DEVICE_NAME);
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS       status;

    UNREFERENCED_PARAMETER(RegistryPath);

    // Control device: secure open, with an explicit DACL granting full access
    // only to SYSTEM and the local Administrators group. This is a hypervisor
    // control channel, so a plain IoCreateDevice (which would inherit a default
    // SD that can permit non-admin opens) is not acceptable.
    DECLARE_CONST_UNICODE_STRING(sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    status = IoCreateDeviceSecure(DriverObject,
                                  0,                    // no device extension
                                  &ntDeviceName,
                                  FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN,
                                  FALSE,                // exclusive = FALSE
                                  &sddl,
                                  &GUID_DEVCLASS_HVDBG,
                                  &deviceObject);
    if (!NT_SUCCESS(status))
        return status;

    // \DosDevices symlink so user mode can CreateFile(\\.\HvDbg).
    status = IoCreateSymbolicLink(&g_DosDeviceName, &ntDeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    // IOCTLs carry HVDBG_INFO via METHOD_BUFFERED -> buffered I/O.
    deviceObject->Flags |= DO_BUFFERED_IO;

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = HvDbgCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = HvDbgCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HvDbgDeviceControl;
    DriverObject->DriverUnload                         = HvDbgUnload;

    // Device is ready for I/O.
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
