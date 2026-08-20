#include <ntddk.h>
#include <wdm.h>
#include <wdmsec.h>         // IoCreateDeviceSecure
#include <intrin.h>         // __rdmsr, __readgsqword
#pragma intrinsic(__readmsr)

#ifndef _WIN64
#error "This driver targets 64-bit Windows only."
#endif

// ================================================================
//  IOCTL codes
//  (must match the ring-3 header)
// ================================================================
#define IOCTL_GDRV_READ_PHYSICAL    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GDRV_READ_VIRTUAL     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GDRV_PATTERN_SCAN     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GDRV_READ_MSR         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GDRV_GET_PHYS_RANGES  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_GDRV_GET_KERNEL_INFO  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_ANY_ACCESS)

// ================================================================
//  Limits
// ================================================================
#define MAX_RW_SIZE         0x100000    //  1 MB
#define MAX_SCAN_SIZE       0x2000000   // 32 MB
#define MAX_PATTERN_BYTES   64
#define MAX_PHYS_RANGES     128

// ================================================================
//  Internal kernel types (x64 offsets)
// ================================================================
typedef struct _KLDR_DATA_TABLE_ENTRY_EX {
    LIST_ENTRY      InLoadOrderLinks;   // 0x00
    PVOID           ExceptionTable;     // 0x10
    ULONG           ExceptionTableSize; // 0x18
    ULONG           _Pad0;              // 0x1C
    PVOID           GpValue;            // 0x20
    PVOID           NonPagedDebugInfo;  // 0x28
    PVOID           DllBase;            // 0x30  ← ntoskrnl load base
    PVOID           EntryPoint;         // 0x38
    ULONG           SizeOfImage;        // 0x40  ← image size in bytes
    ULONG           _Pad1;              // 0x44
    UNICODE_STRING  FullDllName;        // 0x48
    UNICODE_STRING  BaseDllName;        // 0x58
} KLDR_DATA_TABLE_ENTRY_EX, * PKLDR_DATA_TABLE_ENTRY_EX;

// Compile-time offset checks – will error if Windows changes the layout
C_ASSERT(FIELD_OFFSET(KLDR_DATA_TABLE_ENTRY_EX, DllBase) == 0x30);
C_ASSERT(FIELD_OFFSET(KLDR_DATA_TABLE_ENTRY_EX, SizeOfImage) == 0x40);

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PULONG_PTR  Base;       // → KiServiceTable
    PULONG      Count;      // unused on x64
    ULONG       Limit;      // number of syscalls
    PUCHAR      Number;     // argument table
} KSERVICE_TABLE_DESCRIPTOR, * PKSERVICE_TABLE_DESCRIPTOR;

// ================================================================
//  Shared IOCTL structures (binary-compatible with ring-3)
// ================================================================

// ---- READ_PHYSICAL ----------------------------------------------
typedef struct _READ_PHYSICAL_INPUT {
    ULONG64 PhysicalAddress;
    ULONG   Size;
} READ_PHYSICAL_INPUT, * PREAD_PHYSICAL_INPUT;

// ---- READ_VIRTUAL -----------------------------------------------
typedef struct _READ_VIRTUAL_INPUT {
    ULONG64 VirtualAddress;
    ULONG   Size;
} READ_VIRTUAL_INPUT, * PREAD_VIRTUAL_INPUT;

// ---- PATTERN_SCAN -----------------------------------------------
typedef struct _PATTERN_SCAN_INPUT {
    ULONG64 SearchBase;
    ULONG   SearchSize;
    ULONG   PatternSize;
    UCHAR   Pattern[MAX_PATTERN_BYTES];
    UCHAR   Mask[MAX_PATTERN_BYTES];      // 'x' = exact, '?' = wildcard
} PATTERN_SCAN_INPUT, * PPATTERN_SCAN_INPUT;

typedef struct _PATTERN_SCAN_OUTPUT {
    ULONG64 FoundAddress;
} PATTERN_SCAN_OUTPUT, * PPATTERN_SCAN_OUTPUT;

// ---- READ_MSR ---------------------------------------------------
typedef struct _READ_MSR_INPUT {
    ULONG MsrIndex;
} READ_MSR_INPUT, * PREAD_MSR_INPUT;

typedef struct _READ_MSR_OUTPUT {
    ULONG64 Value;
} READ_MSR_OUTPUT, * PREAD_MSR_OUTPUT;

// ---- GET_PHYS_RANGES --------------------------------------------
typedef struct _PHYS_RANGE_ENTRY {
    ULONG64 BaseAddress;
    ULONG64 NumberOfBytes;
} PHYS_RANGE_ENTRY;

typedef struct _PHYS_RANGES_OUTPUT {
    ULONG          Count;
    ULONG          _Pad;
    PHYS_RANGE_ENTRY Ranges[MAX_PHYS_RANGES];
} PHYS_RANGES_OUTPUT, * PPHYS_RANGES_OUTPUT;

// ---- GET_KERNEL_INFO --------------------------------------------
typedef struct _KERNEL_INFO_OUTPUT {
    ULONG64 NtoskrnlBase;
    ULONG   NtoskrnlSize;
    ULONG   _Pad;
    ULONG64 PsLoadedModuleListAddr;
    ULONG64 PsInitialSystemProcessAddr;
    ULONG64 KeServiceDescriptorTableAddr;
    ULONG64 KdVersionBlockAddr;
    ULONG64 KpcrAddr;
} KERNEL_INFO_OUTPUT, * PKERNEL_INFO_OUTPUT;

// ================================================================
//  Global kernel addresses (cached at DriverEntry)
// ================================================================
static ULONG64 g_NtoskrnlBase = 0;
static ULONG   g_NtoskrnlSize = 0;
static ULONG64 g_PsLoadedModuleListAddr = 0;
static ULONG64 g_PsInitialSystemProcessAddr = 0;
static ULONG64 g_KeServiceDescriptorTableAddr = 0;
static ULONG64 g_KdVersionBlockAddr = 0;

// ================================================================
//  Helper – resolve an exported kernel symbol by name
// ================================================================
static ULONG64 ResolveSymbol(PCWSTR name) {
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, name);
    return (ULONG64)MmGetSystemRoutineAddress(&us);
}

// ================================================================
//  Physical memory read (handles unaligned PA)
// ================================================================
static NTSTATUS ReadPhysicalMemorySafe(PVOID userBuf, ULONG64 physAddr, ULONG size) {
    ULONG64          aligned = physAddr & ~(ULONG64)(PAGE_SIZE - 1);
    ULONG            offset = (ULONG)(physAddr - aligned);
    ULONG            mapSize = (size + offset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = aligned;

    PVOID mapped = MmMapIoSpace(pa, mapSize, MmCached);
    if (!mapped) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS s;
    __try {
        ProbeForWrite(userBuf, size, sizeof(UCHAR));
        RtlCopyMemory(userBuf, (PUCHAR)mapped + offset, size);
        s = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        s = GetExceptionCode();
    }

    MmUnmapIoSpace(mapped, mapSize);
    return s;
}

// ================================================================
//  Kernel virtual memory read
// ================================================================
static NTSTATUS ReadVirtualMemorySafe(PVOID userBuf, ULONG64 virtAddr, ULONG size) {
    NTSTATUS s;
    __try {
        ProbeForWrite(userBuf, size, sizeof(UCHAR));
        RtlCopyMemory(userBuf, (PVOID)(ULONG_PTR)virtAddr, size);
        s = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        s = GetExceptionCode();
    }
    return s;
}

// ================================================================
//  Kernel pattern scanner (page-fault resilient)
// ================================================================
static ULONG64 ScanKernelPattern(ULONG64 base, ULONG size,
    const UCHAR* pat, const UCHAR* mask,
    ULONG patLen)
{
    if (patLen == 0 || size < patLen) return 0;

    PUCHAR p = (PUCHAR)(ULONG_PTR)base;
    ULONG  limit = size - patLen;
    ULONG  i = 0;

    while (i <= limit) {
        BOOLEAN hit = FALSE;
        BOOLEAN fault = FALSE;

        __try {
            hit = TRUE;
            for (ULONG j = 0; j < patLen; j++) {
                if (mask[j] == 'x' && p[i + j] != pat[j]) {
                    hit = FALSE;
                    break;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            hit = FALSE;
            fault = TRUE;
        }

        if (hit) return base + i;

        if (fault) {
            // Jump to next page boundary
            ULONG64 nextPage = ((ULONG64)(p + i) + PAGE_SIZE) & ~(ULONG64)(PAGE_SIZE - 1);
            ULONG   skip = (ULONG)(nextPage - (ULONG64)(p + i));
            i += (skip > 0) ? skip : PAGE_SIZE;
        }
        else {
            i++;
        }
    }
    return 0;
}

// ================================================================
//  MSR read (GP-fault safe)
// ================================================================
static NTSTATUS ReadMsrSafe(ULONG idx, PULONG64 out) {
    __try {
        *out = __readmsr(idx);   // ← changed from __rdmsr
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *out = 0;
        return STATUS_ILLEGAL_INSTRUCTION;
    }
}

// ================================================================
//  Physical memory ranges
// ================================================================
static NTSTATUS FillPhysicalRanges(PVOID userBuf, ULONG outLen) {
    if (outLen < sizeof(PHYS_RANGES_OUTPUT)) return STATUS_BUFFER_TOO_SMALL;

    PPHYSICAL_MEMORY_RANGE sys = MmGetPhysicalMemoryRanges();
    if (!sys) return STATUS_UNSUCCESSFUL;

    ULONG count = 0;
    while ((sys[count].BaseAddress.QuadPart | sys[count].NumberOfBytes.QuadPart) != 0
        && count < MAX_PHYS_RANGES) {
        count++;
    }

    NTSTATUS s;
    __try {
        ProbeForWrite(userBuf, sizeof(PHYS_RANGES_OUTPUT), sizeof(UCHAR));
        PPHYS_RANGES_OUTPUT out = (PPHYS_RANGES_OUTPUT)userBuf;
        out->Count = count;
        out->_Pad = 0;
        for (ULONG i = 0; i < count; i++) {
            out->Ranges[i].BaseAddress = sys[i].BaseAddress.QuadPart;
            out->Ranges[i].NumberOfBytes = sys[i].NumberOfBytes.QuadPart;
        }
        s = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        s = GetExceptionCode();
    }

    ExFreePool(sys);
    return s;
}

// ================================================================
//  IOCTL dispatcher
// ================================================================
NTSTATUS DeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);

    PIO_STACK_LOCATION stk = IoGetCurrentIrpStackLocation(irp);
    ULONG              code = stk->Parameters.DeviceIoControl.IoControlCode;
    ULONG              inLen = stk->Parameters.DeviceIoControl.InputBufferLength;
    ULONG              outLen = stk->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS           s = STATUS_UNSUCCESSFUL;

    irp->IoStatus.Information = 0;

    // ---- 0x800  READ_PHYSICAL -------------------------------------------
    if (code == IOCTL_GDRV_READ_PHYSICAL) {
        if (inLen < sizeof(READ_PHYSICAL_INPUT)) { s = STATUS_BUFFER_TOO_SMALL; goto done; }

        PREAD_PHYSICAL_INPUT raw = (PREAD_PHYSICAL_INPUT)
            stk->Parameters.DeviceIoControl.Type3InputBuffer;
        READ_PHYSICAL_INPUT in;
        __try {
            ProbeForRead(raw, sizeof(in), __alignof(READ_PHYSICAL_INPUT));
            in = *raw;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { s = STATUS_ACCESS_VIOLATION; goto done; }

        if (!in.Size || in.Size > MAX_RW_SIZE) { s = STATUS_INVALID_PARAMETER;   goto done; }
        if (in.PhysicalAddress < 0x1000) { s = STATUS_INVALID_PARAMETER;   goto done; }
        if (outLen < in.Size) { s = STATUS_BUFFER_TOO_SMALL;    goto done; }
        if (!irp->UserBuffer) { s = STATUS_INVALID_USER_BUFFER; goto done; }

        s = ReadPhysicalMemorySafe(irp->UserBuffer, in.PhysicalAddress, in.Size);
        if (NT_SUCCESS(s)) irp->IoStatus.Information = in.Size;
    }

    // ---- 0x801  READ_VIRTUAL --------------------------------------------
    else if (code == IOCTL_GDRV_READ_VIRTUAL) {
        if (inLen < sizeof(READ_VIRTUAL_INPUT)) { s = STATUS_BUFFER_TOO_SMALL; goto done; }

        PREAD_VIRTUAL_INPUT raw = (PREAD_VIRTUAL_INPUT)
            stk->Parameters.DeviceIoControl.Type3InputBuffer;
        READ_VIRTUAL_INPUT in;
        __try {
            ProbeForRead(raw, sizeof(in), __alignof(READ_VIRTUAL_INPUT));
            in = *raw;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { s = STATUS_ACCESS_VIOLATION; goto done; }

        if (!in.Size || in.Size > MAX_RW_SIZE) { s = STATUS_INVALID_PARAMETER;   goto done; }
        if (in.VirtualAddress < 0xFFFF800000000000ULL) { s = STATUS_INVALID_PARAMETER;   goto done; }
        if (outLen < in.Size) { s = STATUS_BUFFER_TOO_SMALL;    goto done; }
        if (!irp->UserBuffer) { s = STATUS_INVALID_USER_BUFFER; goto done; }

        s = ReadVirtualMemorySafe(irp->UserBuffer, in.VirtualAddress, in.Size);
        if (NT_SUCCESS(s)) irp->IoStatus.Information = in.Size;
    }

    // ---- 0x802  PATTERN_SCAN --------------------------------------------
    else if (code == IOCTL_GDRV_PATTERN_SCAN) {
        if (inLen < sizeof(PATTERN_SCAN_INPUT)) { s = STATUS_BUFFER_TOO_SMALL; goto done; }
        if (outLen < sizeof(PATTERN_SCAN_OUTPUT)) { s = STATUS_BUFFER_TOO_SMALL; goto done; }

        PPATTERN_SCAN_INPUT raw = (PPATTERN_SCAN_INPUT)
            stk->Parameters.DeviceIoControl.Type3InputBuffer;
        PATTERN_SCAN_INPUT in;
        __try {
            ProbeForRead(raw, sizeof(in), __alignof(PATTERN_SCAN_INPUT));
            in = *raw;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { s = STATUS_ACCESS_VIOLATION; goto done; }

        if (!in.PatternSize || in.PatternSize > MAX_PATTERN_BYTES) { s = STATUS_INVALID_PARAMETER;   goto done; }
        if (!in.SearchSize || in.SearchSize > MAX_SCAN_SIZE) { s = STATUS_INVALID_PARAMETER;   goto done; }
        if (in.SearchBase < 0xFFFF800000000000ULL) { s = STATUS_INVALID_PARAMETER;   goto done; }
        if (!irp->UserBuffer) { s = STATUS_INVALID_USER_BUFFER; goto done; }

        ULONG64 found = ScanKernelPattern(
            in.SearchBase, in.SearchSize,
            in.Pattern, in.Mask, in.PatternSize);

        __try {
            ProbeForWrite(irp->UserBuffer, sizeof(PATTERN_SCAN_OUTPUT), sizeof(UCHAR));
            ((PPATTERN_SCAN_OUTPUT)irp->UserBuffer)->FoundAddress = found;
            s = STATUS_SUCCESS;
            irp->IoStatus.Information = sizeof(PATTERN_SCAN_OUTPUT);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            s = GetExceptionCode();
        }
    }

    // ---- 0x803  READ_MSR ------------------------------------------------
    else if (code == IOCTL_GDRV_READ_MSR) {
        if (inLen < sizeof(READ_MSR_INPUT)) { s = STATUS_BUFFER_TOO_SMALL; goto done; }
        if (outLen < sizeof(READ_MSR_OUTPUT)) { s = STATUS_BUFFER_TOO_SMALL; goto done; }

        PREAD_MSR_INPUT raw = (PREAD_MSR_INPUT)
            stk->Parameters.DeviceIoControl.Type3InputBuffer;
        READ_MSR_INPUT in;
        __try {
            ProbeForRead(raw, sizeof(in), __alignof(READ_MSR_INPUT));
            in = *raw;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { s = STATUS_ACCESS_VIOLATION; goto done; }

        if (!irp->UserBuffer) { s = STATUS_INVALID_USER_BUFFER; goto done; }

        ULONG64 val = 0;
        s = ReadMsrSafe(in.MsrIndex, &val);
        if (NT_SUCCESS(s)) {
            __try {
                ProbeForWrite(irp->UserBuffer, sizeof(READ_MSR_OUTPUT), sizeof(UCHAR));
                ((PREAD_MSR_OUTPUT)irp->UserBuffer)->Value = val;
                irp->IoStatus.Information = sizeof(READ_MSR_OUTPUT);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                s = GetExceptionCode();
            }
        }
    }

    // ---- 0x804  GET_PHYS_RANGES  ----------------------------------------
    else if (code == IOCTL_GDRV_GET_PHYS_RANGES) {
        if (outLen < sizeof(PHYS_RANGES_OUTPUT)) { s = STATUS_BUFFER_TOO_SMALL;    goto done; }
        if (!irp->UserBuffer) { s = STATUS_INVALID_USER_BUFFER; goto done; }

        s = FillPhysicalRanges(irp->UserBuffer, outLen);
        if (NT_SUCCESS(s)) irp->IoStatus.Information = sizeof(PHYS_RANGES_OUTPUT);
    }

    // ---- 0x805  GET_KERNEL_INFO  ----------------------------------------
    else if (code == IOCTL_GDRV_GET_KERNEL_INFO) {
        if (outLen < sizeof(KERNEL_INFO_OUTPUT)) { s = STATUS_BUFFER_TOO_SMALL;    goto done; }
        if (!irp->UserBuffer) { s = STATUS_INVALID_USER_BUFFER; goto done; }

        KERNEL_INFO_OUTPUT info;
        info.NtoskrnlBase = g_NtoskrnlBase;
        info.NtoskrnlSize = g_NtoskrnlSize;
        info._Pad = 0;
        info.PsLoadedModuleListAddr = g_PsLoadedModuleListAddr;
        info.PsInitialSystemProcessAddr = g_PsInitialSystemProcessAddr;
        info.KeServiceDescriptorTableAddr = g_KeServiceDescriptorTableAddr;
        info.KdVersionBlockAddr = g_KdVersionBlockAddr;
        info.KpcrAddr = __readgsqword(0x18);

        __try {
            ProbeForWrite(irp->UserBuffer, sizeof(info), sizeof(UCHAR));
            RtlCopyMemory(irp->UserBuffer, &info, sizeof(info));
            s = STATUS_SUCCESS;
            irp->IoStatus.Information = sizeof(info);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            s = GetExceptionCode();
        }
    }

    else {
        s = STATUS_INVALID_DEVICE_REQUEST;
    }

done:
    irp->IoStatus.Status = s;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return s;
}

// ================================================================
//  Create / Close
// ================================================================
NTSTATUS CreateClose(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ================================================================
//  Unload
// ================================================================
VOID DriverUnload(PDRIVER_OBJECT driverObject) {
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\MyGdrv");
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(driverObject->DeviceObject);
}

// ================================================================
//  DriverEntry
// ================================================================
NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);

    // ------------------------------------------------------------------
    // 1. Cache exported kernel symbol addresses.
    //    MmGetSystemRoutineAddress is PASSIVE_LEVEL-only; call once.
    // ------------------------------------------------------------------
    g_PsLoadedModuleListAddr = ResolveSymbol(L"PsLoadedModuleList");
    g_PsInitialSystemProcessAddr = ResolveSymbol(L"PsInitialSystemProcess");
    g_KeServiceDescriptorTableAddr = ResolveSymbol(L"KeServiceDescriptorTable");
    g_KdVersionBlockAddr = ResolveSymbol(L"KdVersionBlock");

    // ntoskrnl base + size from PsLoadedModuleList first entry
    if (g_PsLoadedModuleListAddr) {
        __try {
            PLIST_ENTRY head = (PLIST_ENTRY)(ULONG_PTR)g_PsLoadedModuleListAddr;
            if (!IsListEmpty(head)) {
                PKLDR_DATA_TABLE_ENTRY_EX e = CONTAINING_RECORD(
                    head->Flink, KLDR_DATA_TABLE_ENTRY_EX, InLoadOrderLinks);
                g_NtoskrnlBase = (ULONG64)e->DllBase;
                g_NtoskrnlSize = e->SizeOfImage;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { /* leave zeros */ }
    }

    // ------------------------------------------------------------------
    // 2. Create the device, restricted to SYSTEM + Administrators.
    // ------------------------------------------------------------------
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\MyGdrv");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\MyGdrv");
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    GUID           classGuid = { 0 };

    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS s = IoCreateDeviceSecure(
        driverObject, 0, &deviceName,
        FILE_DEVICE_UNKNOWN, 0, FALSE,
        &sddl, &classGuid, &deviceObject);
    if (!NT_SUCCESS(s)) return s;

    s = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(s)) {
        IoDeleteDevice(deviceObject);
        return s;
    }

    driverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    driverObject->DriverUnload = DriverUnload;

    // Clear the initializing flag – mandatory for legacy drivers
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}