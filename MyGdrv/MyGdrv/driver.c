// ================================================================
//  GDRV – Ring{0/-1/-2/-3} Forensics Kernel Driver
//  Build: WDK 10.0.19041.0+, x64, NTDDI_WIN10
// ================================================================

#include <ntddk.h>
#include <wdm.h>
#include <wdmsec.h>
#include <intrin.h>

#ifndef _WIN64
#error "64-bit only."
#endif

// -----------------------------------------------------------------
// Missing WDK declarations
// -----------------------------------------------------------------
NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG  Class, PVOID Info, ULONG Len, PULONG Ret);

// -----------------------------------------------------------------
// IOCTL codes – copy to ring-3 header
// -----------------------------------------------------------------
#define GDRV_CTL(n) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800+(n), METHOD_NEITHER, FILE_ANY_ACCESS)

#define IOCTL_GDRV_READ_PHYSICAL        GDRV_CTL(0x00)
#define IOCTL_GDRV_READ_VIRTUAL         GDRV_CTL(0x01)
#define IOCTL_GDRV_PATTERN_SCAN         GDRV_CTL(0x02)
#define IOCTL_GDRV_READ_MSR             GDRV_CTL(0x03)
#define IOCTL_GDRV_GET_PHYS_RANGES      GDRV_CTL(0x04)
#define IOCTL_GDRV_GET_KERNEL_INFO      GDRV_CTL(0x05)
#define IOCTL_GDRV_READ_PCI_CONFIG      GDRV_CTL(0x06)
#define IOCTL_GDRV_SCAN_PCI_BARS        GDRV_CTL(0x07)
#define IOCTL_GDRV_READ_ACPI_TABLE      GDRV_CTL(0x08)
#define IOCTL_GDRV_CHECK_VMX            GDRV_CTL(0x09)
#define IOCTL_GDRV_CHECK_SMM            GDRV_CTL(0x0A)
#define IOCTL_GDRV_READ_UEFI_VAR        GDRV_CTL(0x0B)
#define IOCTL_GDRV_READ_IO_PORT         GDRV_CTL(0x0C)
#define IOCTL_GDRV_ENUMERATE_CALLBACKS  GDRV_CTL(0x0D)
#define IOCTL_GDRV_DETECT_SSDT_HOOKS    GDRV_CTL(0x0E)
#define IOCTL_GDRV_READ_KPCR            GDRV_CTL(0x0F)
#define IOCTL_GDRV_SCAN_HIDDEN_DRIVERS  GDRV_CTL(0x10)
#define IOCTL_GDRV_CHECK_IOMMU          GDRV_CTL(0x11)
#define IOCTL_GDRV_CHECK_HYPERVISOR     GDRV_CTL(0x12)
#define IOCTL_GDRV_WRITE_MSR            GDRV_CTL(0x13)   // <-- NEW

// -----------------------------------------------------------------
// Limits
// -----------------------------------------------------------------
#define MAX_RW_SIZE             0x100000
#define MAX_SCAN_SIZE           0x2000000
#define MAX_PATTERN_BYTES       64
#define MAX_PHYS_RANGES         128
#define MAX_PCI_DEVICES         256
#define MAX_SSDT_ENTRIES        512
#define MAX_CALLBACK_ENTRIES    64
#define MAX_HIDDEN_DRIVERS      128
#define MAX_ACPI_TABLE_SIZE     (128 * 1024)

// -----------------------------------------------------------------
// Shared structures (must match ring-3)
// -----------------------------------------------------------------
typedef struct _READ_PHYSICAL_INPUT { ULONG64 PhysicalAddress; ULONG Size; } READ_PHYSICAL_INPUT, * PREAD_PHYSICAL_INPUT;
typedef struct _READ_VIRTUAL_INPUT { ULONG64 VirtualAddress;  ULONG Size; } READ_VIRTUAL_INPUT, * PREAD_VIRTUAL_INPUT;

typedef struct _PATTERN_SCAN_INPUT {
    ULONG64 SearchBase;
    ULONG   SearchSize;
    ULONG   PatternSize;
    UCHAR   Pattern[MAX_PATTERN_BYTES];
    UCHAR   Mask[MAX_PATTERN_BYTES];
} PATTERN_SCAN_INPUT, * PPATTERN_SCAN_INPUT;
typedef struct _PATTERN_SCAN_OUTPUT { ULONG64 FoundAddress; } PATTERN_SCAN_OUTPUT, * PPATTERN_SCAN_OUTPUT;

typedef struct _READ_MSR_INPUT { ULONG MsrIndex; }   READ_MSR_INPUT, * PREAD_MSR_INPUT;
typedef struct _READ_MSR_OUTPUT { ULONG64 Value; }     READ_MSR_OUTPUT, * PREAD_MSR_OUTPUT;

// ---- NEW WRITE_MSR ----
typedef struct _WRITE_MSR_INPUT {
    ULONG MsrIndex;
    ULONG64 Value;
} WRITE_MSR_INPUT, * PWRITE_MSR_INPUT;

typedef struct _PHYS_RANGE_ENTRY { ULONG64 BaseAddress; ULONG64 NumberOfBytes; } PHYS_RANGE_ENTRY;
typedef struct _PHYS_RANGES_OUTPUT {
    ULONG           Count; ULONG _Pad;
    PHYS_RANGE_ENTRY Ranges[MAX_PHYS_RANGES];
} PHYS_RANGES_OUTPUT, * PPHYS_RANGES_OUTPUT;

typedef struct _KERNEL_INFO_OUTPUT {
    ULONG64 NtoskrnlBase;
    ULONG   NtoskrnlSize;      ULONG _Pad;
    ULONG64 PsLoadedModuleListAddr;
    ULONG64 PsInitialSystemProcessAddr;
    ULONG64 KeServiceDescriptorTableAddr;
    ULONG64 KdVersionBlockAddr;
    ULONG64 KpcrAddr;
} KERNEL_INFO_OUTPUT, * PKERNEL_INFO_OUTPUT;

// ---- PCI config ----
typedef struct _PCI_CONFIG_INPUT {
    UCHAR Bus, Device, Function, _Pad;
    ULONG Offset;
    ULONG Size;
} PCI_CONFIG_INPUT, * PPCI_CONFIG_INPUT;

// ---- PCI BAR scan ----
typedef struct _SCAN_PCI_INPUT {
    UCHAR StartBus;
    UCHAR EndBus;
    UCHAR _Pad[2];
} SCAN_PCI_INPUT, * PSCAN_PCI_INPUT;

#define SUSP_KNOWN_FPGA_VID         (1u<<0)
#define SUSP_BUS_MASTER_ENABLED     (1u<<1)
#define SUSP_LARGE_PREFETCH_BAR     (1u<<2)
#define SUSP_ZERO_SUBSYSTEM         (1u<<3)
#define SUSP_UNKNOWN_CLASS          (1u<<4)
#define SUSP_MULTI_LARGE_BARS       (1u<<5)
#define SUSP_KNOWN_ATTACK_ID        (1u<<6)
#define SUSP_64BIT_BAR_ONLY         (1u<<7)

typedef struct _PCI_BAR_INFO {
    ULONG64 Address;
    UCHAR   Type;      // 0=Mem32, 1=Mem64, 2=IO
    BOOLEAN Prefetchable;
    UCHAR   Index;
    UCHAR   _Pad[5];
} PCI_BAR_INFO;

typedef struct _PCI_DEVICE_INFO {
    UCHAR       Bus, Device, Function, _Pad;
    USHORT      VendorID, DeviceID;
    USHORT      SubVendorID, SubDeviceID;
    UCHAR       BaseClass, SubClass, ProgIF, RevisionID;
    USHORT      Command;
    UCHAR       HeaderType;
    UCHAR       CapPtr;
    ULONG       SuspicionFlags;
    PCI_BAR_INFO BARs[6];
} PCI_DEVICE_INFO, * PPCI_DEVICE_INFO;

typedef struct _PCI_SCAN_OUTPUT {
    ULONG          DeviceCount; ULONG _Pad;
    PCI_DEVICE_INFO Devices[MAX_PCI_DEVICES];
} PCI_SCAN_OUTPUT, * PPCI_SCAN_OUTPUT;

// ---- ACPI ----
typedef struct _ACPI_TABLE_INPUT { ULONG Signature; } ACPI_TABLE_INPUT, * PACPI_TABLE_INPUT;

// ---- VMX ----
typedef struct _VMX_INFO {
    BOOLEAN VmxSupported;
    BOOLEAN VmxEnabled;
    BOOLEAN LockBitSet;
    BOOLEAN VmxCurrentlyActive;
    BOOLEAN SmxEnabled;
    BOOLEAN EferLma;
    UCHAR   _Pad[2];
    ULONG64 FeatureControlMsr;
    ULONG64 VmxBasicMsr;
    ULONG64 Cr0Value;
    ULONG64 Cr4Value;
    ULONG64 EferValue;
    ULONG64 LstarMsr;
} VMX_INFO, * PVMX_INFO;

// ---- SMM ----
typedef struct _SMM_INFO {
    BOOLEAN SmrrSupported;
    BOOLEAN SmrrEnabled;
    BOOLEAN SmramAccessible;
    BOOLEAN DualMonitorMode;
    UCHAR   _Pad[4];
    ULONG64 SmrrPhysBase;
    ULONG64 SmrrPhysMask;
    ULONG64 SmramBase;
    ULONG64 SmramSize;
    ULONG64 SmmMonitorCtl;
    USHORT  SmiCmdPort;
    UCHAR   ApmCmdPort;
    UCHAR   ApmStsPort;
    UCHAR   _Pad2[4];
} SMM_INFO, * PSMM_INFO;

// ---- UEFI var ----
typedef struct _UEFI_VAR_INPUT {
    GUID   VendorGuid;
    ULONG  NameChars;
    ULONG  _Pad;
    WCHAR  VariableName[128];
} UEFI_VAR_INPUT, * PUEFI_VAR_INPUT;

typedef struct _UEFI_VAR_OUTPUT {
    ULONG  Attributes;
    ULONG  DataLength;
    UCHAR  Data[4096];
} UEFI_VAR_OUTPUT, * PUEFI_VAR_OUTPUT;

// ---- I/O port ----
typedef struct _IO_PORT_INPUT { USHORT Port; UCHAR Width; UCHAR _Pad; } IO_PORT_INPUT, * PIO_PORT_INPUT;
typedef struct _IO_PORT_OUTPUT { ULONG  Value; } IO_PORT_OUTPUT, * PIO_PORT_OUTPUT;

// ---- Callbacks ----
typedef struct _ENUM_CALLBACKS_INPUT {
    ULONG64 ArrayBase;
    ULONG   EntryCount;
    ULONG   FunctionOffset;
} ENUM_CALLBACKS_INPUT, * PENUM_CALLBACKS_INPUT;

typedef struct _CALLBACK_ENTRY {
    ULONG64 RawFastRef;
    ULONG64 BlockAddress;
    ULONG64 FunctionAddress;
    ULONG64 Context;
} CALLBACK_ENTRY, * PCALLBACK_ENTRY;

typedef struct _ENUM_CALLBACKS_OUTPUT {
    ULONG          ValidCount; ULONG _Pad;
    CALLBACK_ENTRY Entries[MAX_CALLBACK_ENTRIES];
} ENUM_CALLBACKS_OUTPUT, * PENUM_CALLBACKS_OUTPUT;

// ---- SSDT ----
typedef struct _SSDT_ENTRY {
    ULONG   Index;
    BOOLEAN IsHooked;
    BOOLEAN JmpPatch;
    BOOLEAN IndJmpPatch;
    BOOLEAN MovRaxPatch;
    UCHAR   FirstBytes[8];
    UCHAR   _Pad[3];
    ULONG64 HandlerAddress;
} SSDT_ENTRY, * PSSDT_ENTRY;

typedef struct _SSDT_SCAN_OUTPUT {
    ULONG      TotalEntries;
    ULONG      HookedCount;
    SSDT_ENTRY Entries[MAX_SSDT_ENTRIES];
} SSDT_SCAN_OUTPUT, * PSSDT_SCAN_OUTPUT;

// ---- KPCR ----
typedef struct _KPCR_INFO {
    ULONG64 KpcrAddress;
    ULONG64 GdtBase;
    ULONG64 TssBase;
    ULONG64 UserRsp;
    ULONG64 CurrentPrcbAddress;
    ULONG64 UsedSelf;
    ULONG64 IdtBase;
    ULONG64 KernelGsBase;
    ULONG64 LstarMsr;
    ULONG64 GsBaseMsr;
} KPCR_INFO, * PKPCR_INFO;

// ---- Hidden drivers ----
typedef struct _SCAN_HIDDEN_DRIVERS_INPUT {
    ULONG64 IopDriverListHead;
} SCAN_HIDDEN_DRIVERS_INPUT, * PSCAN_HIDDEN_DRIVERS_INPUT;

#define DRVRFLAG_IN_LDRLIST     (1u<<0)
#define DRVRFLAG_IN_DRVLIST     (1u<<1)
#define DRVRFLAG_IN_OBJDIR      (1u<<2)
#define DRVRFLAG_NO_SECTION     (1u<<3)
#define DRVRFLAG_ANONYMOUS      (1u<<4)
#define DRVRFLAG_HIDDEN         (1u<<5)

typedef struct _DRIVER_ENTRY_INFO {
    ULONG64 DriverObjectAddress;
    ULONG64 DriverStart;
    ULONG   DriverSize;
    ULONG   Flags;
    WCHAR   DriverName[64];
    WCHAR   ModuleName[64];
} DRIVER_ENTRY_INFO, * PDRIVER_ENTRY_INFO;

typedef struct _SCAN_HIDDEN_DRIVERS_OUTPUT {
    ULONG             DriverCount; ULONG _Pad;
    DRIVER_ENTRY_INFO Drivers[MAX_HIDDEN_DRIVERS];
} SCAN_HIDDEN_DRIVERS_OUTPUT, * PSCAN_HIDDEN_DRIVERS_OUTPUT;

// ---- IOMMU ----
typedef struct _IOMMU_INFO {
    BOOLEAN IntelVtdPresent;
    BOOLEAN AmdIommuPresent;
    BOOLEAN TranslationEnabled;
    BOOLEAN RootTableSet;
    BOOLEAN WindowsKdmaprot;
    UCHAR   _Pad[3];
    ULONG64 DmarRegisterBase;
    ULONG   GlobalStatusReg;
    ULONG64 VtdCapability;
    ULONG64 VtdExtCapability;
    UCHAR   DmarHostAddressWidth;
    UCHAR   DmarFlags;
    UCHAR   _Pad2[6];
} IOMMU_INFO, * PIOMMU_INFO;

// ---- Hypervisor ----
typedef struct _HYPERVISOR_INFO {
    BOOLEAN HypervisorPresent;
    BOOLEAN IsHyperV;
    BOOLEAN IsVMware;
    BOOLEAN IsKvm;
    BOOLEAN IsXen;
    BOOLEAN IsVirtualBox;
    UCHAR   _Pad[2];
    CHAR    VendorString[13];
    UCHAR   _Pad2[3];
    ULONG   HvMaxLeaf;
    ULONG   HvInterface;
    ULONG64 TscFreqKhz;
    ULONG64 LstarMsr;
    ULONG64 Cr4;
} HYPERVISOR_INFO, * PHYPERVISOR_INFO;

// -----------------------------------------------------------------
// Internal kernel types
// -----------------------------------------------------------------
typedef struct _KLDR_DATA_TABLE_ENTRY_EX {
    LIST_ENTRY     InLoadOrderLinks;
    PVOID          ExceptionTable;
    ULONG          ExceptionTableSize;
    ULONG          _Pad0;
    PVOID          GpValue;
    PVOID          NonPagedDebugInfo;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    ULONG          _Pad1;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} KLDR_DATA_TABLE_ENTRY_EX, * PKLDR_DATA_TABLE_ENTRY_EX;

C_ASSERT(FIELD_OFFSET(KLDR_DATA_TABLE_ENTRY_EX, DllBase) == 0x30);
C_ASSERT(FIELD_OFFSET(KLDR_DATA_TABLE_ENTRY_EX, SizeOfImage) == 0x40);

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PULONG_PTR Base;
    PULONG     Count;
    ULONG      Limit;
    PUCHAR     Number;
} KSERVICE_TABLE_DESCRIPTOR, * PKSERVICE_TABLE_DESCRIPTOR;

typedef struct _MY_SYSTEM_FIRMWARE_TABLE_INFORMATION {
    ULONG ProviderSignature;
    ULONG Action;
    ULONG TableID;
    ULONG BufferLength;
    UCHAR TableBuffer[1];
} MY_SYSTEM_FIRMWARE_TABLE_INFORMATION, * PMY_SYSTEM_FIRMWARE_TABLE_INFORMATION;

#pragma pack(push, 1)
typedef struct _ACPI_TABLE_HEADER {
    CHAR   Signature[4];
    ULONG  Length;
    UCHAR  Revision;
    UCHAR  Checksum;
    CHAR   OemId[6];
    CHAR   OemTableId[8];
    ULONG  OemRevision;
    CHAR   CreatorId[4];
    ULONG  CreatorRevision;
} ACPI_TABLE_HEADER, * PACPI_TABLE_HEADER;

typedef struct _ACPI_DMAR_HEADER {
    ACPI_TABLE_HEADER Hdr;
    UCHAR             HostAddressWidth;
    UCHAR             Flags;
    UCHAR             Reserved[10];
} ACPI_DMAR_HEADER, * PACPI_DMAR_HEADER;

typedef struct _ACPI_DRHD {
    USHORT  Type;
    USHORT  Length;
    UCHAR   Flags;
    UCHAR   Reserved;
    USHORT  PciSegment;
    ULONG64 RegisterBaseAddress;
} ACPI_DRHD, * PACPI_DRHD;
#pragma pack(pop)

// -----------------------------------------------------------------
// Globals
// -----------------------------------------------------------------
static ULONG64 g_NtoskrnlBase = 0;
static ULONG   g_NtoskrnlSize = 0;
static ULONG64 g_PsLoadedModuleListAddr = 0;
static ULONG64 g_PsInitialSystemProcessAddr = 0;
static ULONG64 g_KeServiceDescriptorTableAddr = 0;
static ULONG64 g_KdVersionBlockAddr = 0;

#define GDRV_TAG 'VRDG'
#define GdrvAlloc(sz)  ExAllocatePoolWithTag(NonPagedPool, (sz), GDRV_TAG)
#define GdrvFree(p)    ExFreePool(p)

// -----------------------------------------------------------------
// Core primitives
// -----------------------------------------------------------------
static ULONG64 ResolveSymbol(PCWSTR name) {
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, name);
    return (ULONG64)MmGetSystemRoutineAddress(&us);
}

static NTSTATUS ReadPhysicalMemorySafe(PVOID userBuf, ULONG64 physAddr, ULONG size) {
    ULONG64 aligned = physAddr & ~(ULONG64)(PAGE_SIZE - 1);
    ULONG offset = (ULONG)(physAddr - aligned);
    ULONG mapSize = (size + offset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    PHYSICAL_ADDRESS pa; pa.QuadPart = aligned;
    PVOID mapped = MmMapIoSpace(pa, mapSize, MmCached);
    if (!mapped) return STATUS_INSUFFICIENT_RESOURCES;
    NTSTATUS s;
    __try {
        ProbeForWrite(userBuf, size, sizeof(UCHAR));
        RtlCopyMemory(userBuf, (PUCHAR)mapped + offset, size);
        s = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { s = GetExceptionCode(); }
    MmUnmapIoSpace(mapped, mapSize);
    return s;
}

static NTSTATUS ReadVirtualMemorySafe(PVOID userBuf, ULONG64 virtAddr, ULONG size) {
    NTSTATUS s;
    __try {
        ProbeForWrite(userBuf, size, sizeof(UCHAR));
        RtlCopyMemory(userBuf, (PVOID)(ULONG_PTR)virtAddr, size);
        s = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { s = GetExceptionCode(); }
    return s;
}

static ULONG64 ScanKernelPattern(ULONG64 base, ULONG size,
    const UCHAR* pat, const UCHAR* mask, ULONG patLen) {
    if (!patLen || size < patLen) return 0;
    PUCHAR p = (PUCHAR)(ULONG_PTR)base;
    ULONG i = 0, limit = size - patLen;
    while (i <= limit) {
        BOOLEAN hit = FALSE, fault = FALSE;
        __try {
            hit = TRUE;
            for (ULONG j = 0; j < patLen; j++)
                if (mask[j] == 'x' && p[i + j] != pat[j]) { hit = FALSE; break; }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { hit = FALSE; fault = TRUE; }
        if (hit) return base + i;
        if (fault) {
            ULONG64 next = ((ULONG64)(p + i) + PAGE_SIZE) & ~(ULONG64)(PAGE_SIZE - 1);
            ULONG skip = (ULONG)(next - (ULONG64)(p + i));
            i += skip ? skip : PAGE_SIZE;
        }
        else i++;
    }
    return 0;
}

static NTSTATUS ReadMsrSafe(ULONG idx, PULONG64 out) {
    __try { *out = __readmsr(idx); return STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) { *out = 0; return STATUS_ILLEGAL_INSTRUCTION; }
}

static NTSTATUS WriteMsrSafe(ULONG idx, ULONG64 value) {
    __try { __writemsr(idx, value); return STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ILLEGAL_INSTRUCTION; }
}

static NTSTATUS FillPhysicalRanges(PVOID userBuf, ULONG outLen) {
    if (outLen < sizeof(PHYS_RANGES_OUTPUT)) return STATUS_BUFFER_TOO_SMALL;
    PPHYSICAL_MEMORY_RANGE sys = MmGetPhysicalMemoryRanges();
    if (!sys) return STATUS_UNSUCCESSFUL;
    ULONG count = 0;
    while ((sys[count].BaseAddress.QuadPart | sys[count].NumberOfBytes.QuadPart) &&
        count < MAX_PHYS_RANGES) count++;
    NTSTATUS s;
    __try {
        ProbeForWrite(userBuf, sizeof(PHYS_RANGES_OUTPUT), sizeof(UCHAR));
        PPHYS_RANGES_OUTPUT out = (PPHYS_RANGES_OUTPUT)userBuf;
        out->Count = count; out->_Pad = 0;
        for (ULONG i = 0; i < count; i++) {
            out->Ranges[i].BaseAddress = sys[i].BaseAddress.QuadPart;
            out->Ranges[i].NumberOfBytes = sys[i].NumberOfBytes.QuadPart;
        }
        s = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { s = GetExceptionCode(); }
    ExFreePool(sys);
    return s;
}

// -----------------------------------------------------------------
// ACPI table helper
// -----------------------------------------------------------------
static NTSTATUS GdrvAcpiGetTable(ULONG tableId, PVOID* ppBuf, PULONG pLen) {
    const ULONG hdrOff = FIELD_OFFSET(MY_SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer);
    const ULONG allocSz = hdrOff + MAX_ACPI_TABLE_SIZE;
    PMY_SYSTEM_FIRMWARE_TABLE_INFORMATION sfti =
        (PMY_SYSTEM_FIRMWARE_TABLE_INFORMATION)GdrvAlloc(allocSz);
    if (!sfti) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(sfti, allocSz);
    sfti->ProviderSignature = 'ACPI';
    sfti->Action = 1;
    sfti->TableID = tableId;
    sfti->BufferLength = MAX_ACPI_TABLE_SIZE;
    ULONG retLen = 0;
    NTSTATUS s = ZwQuerySystemInformation(76, sfti, allocSz, &retLen);
    if (!NT_SUCCESS(s)) { GdrvFree(sfti); return s; }
    ULONG tableSize = sfti->BufferLength;
    if (tableSize == 0 || tableSize > MAX_ACPI_TABLE_SIZE) {
        GdrvFree(sfti);
        return STATUS_INVALID_PARAMETER;
    }
    PVOID buf = GdrvAlloc(tableSize);
    if (!buf) { GdrvFree(sfti); return STATUS_INSUFFICIENT_RESOURCES; }
    RtlCopyMemory(buf, sfti->TableBuffer, tableSize);
    GdrvFree(sfti);
    *ppBuf = buf;
    *pLen = tableSize;
    return STATUS_SUCCESS;
}

// -----------------------------------------------------------------
// PCI config read using port I/O (legacy, works everywhere)
// -----------------------------------------------------------------
static ULONG ReadPciConfigPort(UCHAR bus, UCHAR dev, UCHAR func, UCHAR offset, UCHAR size) {
    ULONG addr = 0x80000000 | (bus << 16) | (dev << 11) | (func << 8) | (offset & 0xFC);
    __outdword(0xCF8, addr);
    ULONG data = __indword(0xCFC);
    if (size == 1) data = (data >> ((offset & 3) * 8)) & 0xFF;
    else if (size == 2) data = (data >> ((offset & 3) * 8)) & 0xFFFF;
    return data;
}

// -----------------------------------------------------------------
// IOCTL handlers
// -----------------------------------------------------------------
static NTSTATUS HandleReadPciConfig(PVOID inBuf, ULONG inLen,
    PVOID userBuf, ULONG outLen,
    PULONG_PTR written) {
    if (inLen < sizeof(PCI_CONFIG_INPUT) || outLen < 1) return STATUS_BUFFER_TOO_SMALL;
    PCI_CONFIG_INPUT in;
    __try { ProbeForRead(inBuf, sizeof(in), __alignof(PCI_CONFIG_INPUT)); in = *(PPCI_CONFIG_INPUT)inBuf; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }
    if (in.Device > 31 || in.Function > 7) return STATUS_INVALID_PARAMETER;
    if (in.Size < 1 || in.Size > 4) return STATUS_INVALID_PARAMETER;
    if (outLen < in.Size) return STATUS_BUFFER_TOO_SMALL;

    ULONG data = ReadPciConfigPort(in.Bus, in.Device, in.Function, (UCHAR)in.Offset, (UCHAR)in.Size);
    __try {
        ProbeForWrite(userBuf, in.Size, sizeof(UCHAR));
        RtlCopyMemory(userBuf, &data, in.Size);
        *written = in.Size;
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}

static BOOLEAN IsFpgaVendor(USHORT vid) {
    return vid == 0x10EE || vid == 0x1172 || vid == 0x1204 || vid == 0x11AA;
}

static NTSTATUS HandleScanPciBars(PVOID inBuf, ULONG inLen,
    PVOID userBuf, ULONG outLen,
    PULONG_PTR written) {
    NTSTATUS s = STATUS_UNSUCCESSFUL;

    if (inLen < sizeof(SCAN_PCI_INPUT)) return STATUS_BUFFER_TOO_SMALL;
    if (outLen < sizeof(PCI_SCAN_OUTPUT)) return STATUS_BUFFER_TOO_SMALL;

    SCAN_PCI_INPUT in;
    __try { ProbeForRead(inBuf, sizeof(in), __alignof(SCAN_PCI_INPUT)); in = *(PSCAN_PCI_INPUT)inBuf; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }

    PPCI_SCAN_OUTPUT out = (PPCI_SCAN_OUTPUT)GdrvAlloc(sizeof(PCI_SCAN_OUTPUT));
    if (!out) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(out, sizeof(PCI_SCAN_OUTPUT));

    UCHAR rawCfg[256];
    for (ULONG bus = in.StartBus; bus <= in.EndBus; bus++) {
        for (ULONG dev = 0; dev <= 31; dev++) {
            for (ULONG func = 0; func <= 7; func++) {
                if (out->DeviceCount >= MAX_PCI_DEVICES) goto scan_done;

                if (ReadPciConfigPort((UCHAR)bus, (UCHAR)dev, (UCHAR)func, 0, 2) == 0xFFFF)
                    continue;

                for (ULONG off = 0; off < 256; off += 4) {
                    ULONG val = ReadPciConfigPort((UCHAR)bus, (UCHAR)dev, (UCHAR)func, (UCHAR)off, 4);
                    RtlCopyMemory(rawCfg + off, &val, 4);
                }
                PPCI_COMMON_CONFIG cfg = (PPCI_COMMON_CONFIG)rawCfg;

                PPCI_DEVICE_INFO d = &out->Devices[out->DeviceCount++];
                d->Bus = (UCHAR)bus; d->Device = (UCHAR)dev; d->Function = (UCHAR)func;
                d->VendorID = cfg->VendorID; d->DeviceID = cfg->DeviceID;
                d->SubVendorID = cfg->u.type0.SubVendorID; d->SubDeviceID = cfg->u.type0.SubSystemID;
                d->BaseClass = cfg->BaseClass; d->SubClass = cfg->SubClass; d->ProgIF = cfg->ProgIf;
                d->RevisionID = cfg->RevisionID; d->Command = cfg->Command;
                d->HeaderType = cfg->HeaderType;
                d->CapPtr = ((cfg->HeaderType & 0x7F) == 0) ? cfg->u.type0.CapabilitiesPtr : 0;

                if (IsFpgaVendor(cfg->VendorID)) d->SuspicionFlags |= SUSP_KNOWN_FPGA_VID;
                if (cfg->Command & 0x0004) d->SuspicionFlags |= SUSP_BUS_MASTER_ENABLED;
                if (cfg->BaseClass == 0xFF) d->SuspicionFlags |= SUSP_UNKNOWN_CLASS;
                if (cfg->u.type0.SubVendorID == 0 || cfg->u.type0.SubSystemID == 0)
                    d->SuspicionFlags |= SUSP_ZERO_SUBSYSTEM;
                if (cfg->VendorID == 0x1234 && cfg->DeviceID == 0x1001)
                    d->SuspicionFlags |= SUSP_KNOWN_ATTACK_ID;

                if ((cfg->HeaderType & 0x7F) == 0) {
                    ULONG largeBars = 0;
                    BOOLEAN has64bitBar = FALSE;
                    for (ULONG i = 0; i < 6; i++) {
                        ULONG bar = cfg->u.type0.BaseAddresses[i];
                        if (bar == 0) continue;
                        PCI_BAR_INFO* b = &d->BARs[i];
                        b->Index = (UCHAR)i;
                        if (bar & 0x1) {
                            b->Type = 2; b->Address = (ULONG64)(bar & ~0x3U);
                        }
                        else {
                            ULONG barType = (bar >> 1) & 0x3;
                            b->Prefetchable = (bar >> 3) & 0x1;
                            if (barType == 0x2 && i < 5) {
                                b->Type = 1;
                                ULONG bar1 = cfg->u.type0.BaseAddresses[i + 1];
                                b->Address = ((ULONG64)(bar & ~0xFU)) | ((ULONG64)bar1 << 32);
                                i++; // consume next BAR
                                has64bitBar = TRUE;
                            }
                            else {
                                b->Type = 0;
                                b->Address = (ULONG64)(bar & ~0xFU);
                            }
                            if (b->Prefetchable && b->Address != 0 &&
                                (b->Address & (64ULL * 1024 * 1024 - 1)) == 0) {
                                d->SuspicionFlags |= SUSP_LARGE_PREFETCH_BAR;
                                largeBars++;
                            }
                        }
                    }
                    if (largeBars >= 2) d->SuspicionFlags |= SUSP_MULTI_LARGE_BARS;
                    if (has64bitBar && d->CapPtr == 0)
                        d->SuspicionFlags |= SUSP_64BIT_BAR_ONLY;
                }

                if (func == 0 && !(cfg->HeaderType & 0x80)) break;
            }
        }
    }

scan_done:
    __try {
        ProbeForWrite(userBuf, sizeof(PCI_SCAN_OUTPUT), sizeof(UCHAR));
        RtlCopyMemory(userBuf, out, sizeof(PCI_SCAN_OUTPUT));
        s = STATUS_SUCCESS;
        *written = sizeof(PCI_SCAN_OUTPUT);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { s = GetExceptionCode(); }

    GdrvFree(out);
    return s;
}

static NTSTATUS HandleReadAcpiTable(PVOID inBuf, ULONG inLen,
    PVOID userBuf, ULONG outLen,
    PULONG_PTR written) {
    if (inLen < sizeof(ACPI_TABLE_INPUT)) return STATUS_BUFFER_TOO_SMALL;
    ACPI_TABLE_INPUT in;
    __try { ProbeForRead(inBuf, sizeof(in), __alignof(ACPI_TABLE_INPUT)); in = *(PACPI_TABLE_INPUT)inBuf; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }
    PVOID tableBuf = NULL; ULONG tableLen = 0;
    NTSTATUS s = GdrvAcpiGetTable(in.Signature, &tableBuf, &tableLen);
    if (!NT_SUCCESS(s)) return s;
    if (outLen < tableLen) { GdrvFree(tableBuf); return STATUS_BUFFER_TOO_SMALL; }
    __try {
        ProbeForWrite(userBuf, tableLen, sizeof(UCHAR));
        RtlCopyMemory(userBuf, tableBuf, tableLen);
        *written = tableLen;
        s = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { s = GetExceptionCode(); }
    GdrvFree(tableBuf);
    return s;
}

static NTSTATUS HandleCheckVmx(PVOID userBuf, ULONG outLen, PULONG_PTR written) {
    if (outLen < sizeof(VMX_INFO)) return STATUS_BUFFER_TOO_SMALL;
    VMX_INFO info; RtlZeroMemory(&info, sizeof(info));
    int cpu[4]; __cpuid(cpu, 1); info.VmxSupported = (cpu[2] >> 5) & 1;
    ReadMsrSafe(0x3A, &info.FeatureControlMsr);
    info.LockBitSet = (info.FeatureControlMsr >> 0) & 1;
    info.VmxEnabled = (info.FeatureControlMsr >> 2) & 1;
    ReadMsrSafe(0x480, &info.VmxBasicMsr);
    info.Cr0Value = __readcr0(); info.Cr4Value = __readcr4();
    info.VmxCurrentlyActive = (info.Cr4Value >> 13) & 1;
    info.SmxEnabled = (info.Cr4Value >> 14) & 1;
    ReadMsrSafe(0xC0000080, &info.EferValue);
    info.EferLma = (info.EferValue >> 10) & 1;
    ReadMsrSafe(0xC0000082, &info.LstarMsr);
    __try { ProbeForWrite(userBuf, sizeof(info), sizeof(UCHAR)); RtlCopyMemory(userBuf, &info, sizeof(info)); *written = sizeof(info); return STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}

static NTSTATUS HandleCheckSmm(PVOID userBuf, ULONG outLen, PULONG_PTR written) {
    if (outLen < sizeof(SMM_INFO)) return STATUS_BUFFER_TOO_SMALL;
    SMM_INFO info; RtlZeroMemory(&info, sizeof(info));
    NTSTATUS smrrBase = ReadMsrSafe(0x1F2, &info.SmrrPhysBase);
    NTSTATUS smrrMask = ReadMsrSafe(0x1F3, &info.SmrrPhysMask);
    info.SmrrSupported = NT_SUCCESS(smrrBase) && NT_SUCCESS(smrrMask);
    if (info.SmrrSupported) {
        info.SmrrEnabled = (info.SmrrPhysMask >> 11) & 1;
        if (info.SmrrEnabled) {
            ULONG64 mask = info.SmrrPhysMask & 0xFFFFF000ULL;
            ULONG64 size = (ULONG64)(~mask & 0xFFFFFFFFULL) + 1;
            info.SmramBase = info.SmrrPhysBase & mask;
            info.SmramSize = size;
            UCHAR testBuf[16] = { 0 };
            PHYSICAL_ADDRESS pa; pa.QuadPart = (LONGLONG)info.SmramBase;
            PVOID mapped = MmMapIoSpace(pa, 16, MmNonCached);
            if (mapped) {
                __try { RtlCopyMemory(testBuf, mapped, 16); info.SmramAccessible = TRUE; }
                __except (EXCEPTION_EXECUTE_HANDLER) { info.SmramAccessible = FALSE; }
                MmUnmapIoSpace(mapped, 16);
            }
        }
    }
    ReadMsrSafe(0x9B, &info.SmmMonitorCtl);
    info.DualMonitorMode = (info.SmmMonitorCtl >> 0) & 1;
    info.ApmCmdPort = READ_PORT_UCHAR((PUCHAR)0xB2);
    info.ApmStsPort = READ_PORT_UCHAR((PUCHAR)0xB3);
    PVOID fadtBuf = NULL; ULONG fadtLen = 0;
    if (NT_SUCCESS(GdrvAcpiGetTable(0x50434146, &fadtBuf, &fadtLen)) && fadtLen > 0x30) {
        info.SmiCmdPort = *(PUSHORT)((PUCHAR)fadtBuf + 0x2C);
        GdrvFree(fadtBuf);
    }
    __try { ProbeForWrite(userBuf, sizeof(info), sizeof(UCHAR)); RtlCopyMemory(userBuf, &info, sizeof(info)); *written = sizeof(info); return STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}

static NTSTATUS HandleReadUefiVar(PVOID inBuf, ULONG inLen,
    PVOID userBuf, ULONG outLen,
    PULONG_PTR written) {
    if (inLen < sizeof(UEFI_VAR_INPUT) || outLen < sizeof(UEFI_VAR_OUTPUT))
        return STATUS_BUFFER_TOO_SMALL;
    UEFI_VAR_INPUT in;
    __try { ProbeForRead(inBuf, sizeof(in), __alignof(UEFI_VAR_INPUT)); in = *(PUEFI_VAR_INPUT)inBuf; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }
    if (in.NameChars == 0 || in.NameChars > 127) return STATUS_INVALID_PARAMETER;
    WCHAR nameBuffer[129] = { 0 };
    RtlCopyMemory(nameBuffer, in.VariableName, in.NameChars * sizeof(WCHAR));
    nameBuffer[in.NameChars] = L'\0';
    UNICODE_STRING varName;
    varName.Buffer = nameBuffer;
    varName.Length = (USHORT)(in.NameChars * sizeof(WCHAR));
    varName.MaximumLength = (USHORT)((in.NameChars + 1) * sizeof(WCHAR));
    UCHAR dataBuf[4096] = { 0 };
    ULONG dataLen = sizeof(dataBuf), attrs = 0;
    NTSTATUS s = ExGetFirmwareEnvironmentVariable(&varName, &in.VendorGuid, dataBuf, &dataLen, &attrs);
    if (!NT_SUCCESS(s)) return s;
    PUEFI_VAR_OUTPUT out = (PUEFI_VAR_OUTPUT)userBuf;
    __try {
        ProbeForWrite(out, sizeof(UEFI_VAR_OUTPUT), sizeof(UCHAR));
        out->Attributes = attrs; out->DataLength = dataLen;
        RtlCopyMemory(out->Data, dataBuf, dataLen);
        *written = FIELD_OFFSET(UEFI_VAR_OUTPUT, Data) + dataLen;
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}

static NTSTATUS HandleReadIoPort(PVOID inBuf, ULONG inLen,
    PVOID userBuf, ULONG outLen,
    PULONG_PTR written) {
    if (inLen < sizeof(IO_PORT_INPUT) || outLen < sizeof(IO_PORT_OUTPUT))
        return STATUS_BUFFER_TOO_SMALL;
    IO_PORT_INPUT in;
    __try { ProbeForRead(inBuf, sizeof(in), __alignof(IO_PORT_INPUT)); in = *(PIO_PORT_INPUT)inBuf; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }
    if (in.Width != 1 && in.Width != 2 && in.Width != 4) return STATUS_INVALID_PARAMETER;
    ULONG value = 0;
    __try {
        switch (in.Width) {
        case 1: value = READ_PORT_UCHAR((PUCHAR)(ULONG_PTR)in.Port); break;
        case 2: value = READ_PORT_USHORT((PUSHORT)(ULONG_PTR)in.Port); break;
        case 4: value = READ_PORT_ULONG((PULONG)(ULONG_PTR)in.Port); break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    PIO_PORT_OUTPUT out = (PIO_PORT_OUTPUT)userBuf;
    __try { ProbeForWrite(out, sizeof(IO_PORT_OUTPUT), sizeof(UCHAR)); out->Value = value; *written = sizeof(IO_PORT_OUTPUT); return STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}

static NTSTATUS HandleEnumerateCallbacks(PVOID inBuf, ULONG inLen,
    PVOID userBuf, ULONG outLen,
    PULONG_PTR written) {
    if (inLen < sizeof(ENUM_CALLBACKS_INPUT) || outLen < sizeof(ENUM_CALLBACKS_OUTPUT))
        return STATUS_BUFFER_TOO_SMALL;
    ENUM_CALLBACKS_INPUT in;
    __try { ProbeForRead(inBuf, sizeof(in), __alignof(ENUM_CALLBACKS_INPUT)); in = *(PENUM_CALLBACKS_INPUT)inBuf; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }
    if (in.ArrayBase < 0xFFFF800000000000ULL || in.EntryCount == 0 || in.EntryCount > MAX_CALLBACK_ENTRIES)
        return STATUS_INVALID_PARAMETER;
    if (in.FunctionOffset > 0x100) return STATUS_INVALID_PARAMETER;
    ENUM_CALLBACKS_OUTPUT out; RtlZeroMemory(&out, sizeof(out));
    PULONG_PTR arr = (PULONG_PTR)(ULONG_PTR)in.ArrayBase;
    for (ULONG i = 0; i < in.EntryCount; i++) {
        ULONG_PTR rawRef = 0;
        __try { rawRef = arr[i]; }
        __except (EXCEPTION_EXECUTE_HANDLER) { break; }
        if (rawRef == 0) continue;
        ULONG_PTR blockAddr = rawRef & ~(ULONG_PTR)0xF;
        if (blockAddr < 0xFFFF800000000000ULL) continue;
        ULONG64 funcAddr = 0, ctxAddr = 0;
        __try {
            funcAddr = *(PULONG64)(blockAddr + in.FunctionOffset);
            ctxAddr = *(PULONG64)(blockAddr + in.FunctionOffset + 8);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (funcAddr == 0) continue;
        PCALLBACK_ENTRY e = &out.Entries[out.ValidCount++];
        e->RawFastRef = (ULONG64)rawRef;
        e->BlockAddress = (ULONG64)blockAddr;
        e->FunctionAddress = funcAddr;
        e->Context = ctxAddr;
    }
    __try { ProbeForWrite(userBuf, sizeof(out), sizeof(UCHAR)); RtlCopyMemory(userBuf, &out, sizeof(out)); *written = sizeof(out); return STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}

static NTSTATUS HandleDetectSsdtHooks(PVOID userBuf, ULONG outLen,
    PULONG_PTR written) {
    if (outLen < sizeof(SSDT_SCAN_OUTPUT)) return STATUS_BUFFER_TOO_SMALL;
    if (!g_KeServiceDescriptorTableAddr || !g_NtoskrnlBase || !g_NtoskrnlSize)
        return STATUS_NOT_FOUND;
    KSERVICE_TABLE_DESCRIPTOR desc;
    __try { desc = *(PKSERVICE_TABLE_DESCRIPTOR)(ULONG_PTR)g_KeServiceDescriptorTableAddr; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }
    if (!desc.Base || !desc.Limit || desc.Limit > MAX_SSDT_ENTRIES)
        return STATUS_INVALID_PARAMETER;
    PSSDT_SCAN_OUTPUT out = (PSSDT_SCAN_OUTPUT)GdrvAlloc(sizeof(SSDT_SCAN_OUTPUT));
    if (!out) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(out, sizeof(SSDT_SCAN_OUTPUT));
    out->TotalEntries = desc.Limit;
    PULONG table = (PULONG)(ULONG_PTR)desc.Base;
    ULONG64 ntBase = g_NtoskrnlBase, ntLimit = ntBase + g_NtoskrnlSize;
    for (ULONG i = 0; i < desc.Limit; i++) {
        ULONG raw = 0; ULONG64 handler = 0;
        __try {
            raw = table[i];
            handler = (ULONG64)((LONG64)(ULONG_PTR)table + (LONG)raw);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        PSSDT_ENTRY e = &out->Entries[i];
        e->Index = i; e->HandlerAddress = handler;
        e->IsHooked = (handler < ntBase || handler >= ntLimit);
        if (e->IsHooked) out->HookedCount++;
        __try { RtlCopyMemory(e->FirstBytes, (PVOID)(ULONG_PTR)handler, 8); }
        __except (EXCEPTION_EXECUTE_HANDLER) { /* leave zeros */ }
        e->JmpPatch = (e->FirstBytes[0] == 0xE9);
        e->IndJmpPatch = (e->FirstBytes[0] == 0xFF && e->FirstBytes[1] == 0x25);
        e->MovRaxPatch = (e->FirstBytes[0] == 0x48 && e->FirstBytes[1] == 0xB8);
    }
    __try { ProbeForWrite(userBuf, sizeof(SSDT_SCAN_OUTPUT), sizeof(UCHAR)); RtlCopyMemory(userBuf, out, sizeof(SSDT_SCAN_OUTPUT)); *written = sizeof(SSDT_SCAN_OUTPUT); return STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}

static NTSTATUS HandleReadKpcr(PVOID userBuf, ULONG outLen, PULONG_PTR written) {
    if (outLen < sizeof(KPCR_INFO)) return STATUS_BUFFER_TOO_SMALL;
    KPCR_INFO info; RtlZeroMemory(&info, sizeof(info));
    info.KpcrAddress = __readgsqword(0x18);
    info.GdtBase = __readgsqword(0x00);
    info.TssBase = __readgsqword(0x08);
    info.UserRsp = __readgsqword(0x10);
    info.CurrentPrcbAddress = __readgsqword(0x20);
    info.UsedSelf = __readgsqword(0x30);
    info.IdtBase = __readgsqword(0x38);
    ReadMsrSafe(0xC0000102, &info.KernelGsBase);
    ReadMsrSafe(0xC0000082, &info.LstarMsr);
    ReadMsrSafe(0xC0000101, &info.GsBaseMsr);
    __try { ProbeForWrite(userBuf, sizeof(info), sizeof(UCHAR)); RtlCopyMemory(userBuf, &info, sizeof(info)); *written = sizeof(info); return STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}

static NTSTATUS HandleScanHiddenDrivers(PVOID inBuf, ULONG inLen,
    PVOID userBuf, ULONG outLen,
    PULONG_PTR written) {
    if (inLen < sizeof(SCAN_HIDDEN_DRIVERS_INPUT) || outLen < sizeof(SCAN_HIDDEN_DRIVERS_OUTPUT))
        return STATUS_BUFFER_TOO_SMALL;
    SCAN_HIDDEN_DRIVERS_INPUT in;
    __try { ProbeForRead(inBuf, sizeof(in), __alignof(SCAN_HIDDEN_DRIVERS_INPUT)); in = *(PSCAN_HIDDEN_DRIVERS_INPUT)inBuf; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_ACCESS_VIOLATION; }
    PSCAN_HIDDEN_DRIVERS_OUTPUT out = (PSCAN_HIDDEN_DRIVERS_OUTPUT)GdrvAlloc(sizeof(SCAN_HIDDEN_DRIVERS_OUTPUT));
    if (!out) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(out, sizeof(SCAN_HIDDEN_DRIVERS_OUTPUT));
    if (g_PsLoadedModuleListAddr) {
        __try {
            PLIST_ENTRY head = (PLIST_ENTRY)(ULONG_PTR)g_PsLoadedModuleListAddr;
            PLIST_ENTRY cur = head->Flink;
            while (cur != head && out->DriverCount < MAX_HIDDEN_DRIVERS) {
                PKLDR_DATA_TABLE_ENTRY_EX ldr = CONTAINING_RECORD(cur, KLDR_DATA_TABLE_ENTRY_EX, InLoadOrderLinks);
                PDRIVER_ENTRY_INFO d = &out->Drivers[out->DriverCount++];
                d->DriverStart = (ULONG64)ldr->DllBase;
                d->DriverSize = ldr->SizeOfImage;
                d->Flags |= DRVRFLAG_IN_LDRLIST;
                if (ldr->BaseDllName.Buffer && ldr->BaseDllName.Length > 0) {
                    ULONG copyLen = min(ldr->BaseDllName.Length, (USHORT)(sizeof(d->ModuleName) - sizeof(WCHAR)));
                    RtlCopyMemory(d->ModuleName, ldr->BaseDllName.Buffer, copyLen);
                }
                cur = cur->Flink;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    if (in.IopDriverListHead && in.IopDriverListHead > 0xFFFF800000000000ULL) {
        __try {
            PLIST_ENTRY head = (PLIST_ENTRY)(ULONG_PTR)in.IopDriverListHead;
            PLIST_ENTRY cur = head->Flink;
            ULONG maxIter = 512;
            while (cur != head && maxIter-- > 0) {
                ULONG64 drvObj = (ULONG64)cur - 0x50; // DRIVER_OBJECT.DriverList offset
                ULONG64 drvBase = 0;
                __try { drvBase = *(PULONG64)(drvObj + 0x18); }
                __except (EXCEPTION_EXECUTE_HANDLER) { cur = cur->Flink; continue; }
                BOOLEAN found = FALSE;
                for (ULONG k = 0; k < out->DriverCount; k++) {
                    if (out->Drivers[k].DriverStart == drvBase) {
                        out->Drivers[k].Flags |= DRVRFLAG_IN_DRVLIST;
                        out->Drivers[k].DriverObjectAddress = drvObj;
                        found = TRUE;
                        break;
                    }
                }
                if (!found && out->DriverCount < MAX_HIDDEN_DRIVERS) {
                    PDRIVER_ENTRY_INFO d = &out->Drivers[out->DriverCount++];
                    d->DriverObjectAddress = drvObj;
                    d->DriverStart = drvBase;
                    d->Flags = DRVRFLAG_IN_DRVLIST | DRVRFLAG_HIDDEN;
                }
                cur = cur->Flink;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    for (ULONG i = 0; i < out->DriverCount; i++) {
        if (!(out->Drivers[i].Flags & DRVRFLAG_IN_LDRLIST))
            out->Drivers[i].Flags |= DRVRFLAG_HIDDEN;
    }
    __try { ProbeForWrite(userBuf, sizeof(SCAN_HIDDEN_DRIVERS_OUTPUT), sizeof(UCHAR)); RtlCopyMemory(userBuf, out, sizeof(SCAN_HIDDEN_DRIVERS_OUTPUT)); *written = sizeof(SCAN_HIDDEN_DRIVERS_OUTPUT); return STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}

static NTSTATUS HandleCheckIommu(PVOID userBuf, ULONG outLen, PULONG_PTR written) {
    if (outLen < sizeof(IOMMU_INFO)) return STATUS_BUFFER_TOO_SMALL;
    IOMMU_INFO info; RtlZeroMemory(&info, sizeof(info));
    PVOID dmarBuf = NULL; ULONG dmarLen = 0;
    if (NT_SUCCESS(GdrvAcpiGetTable(0x52414D44, &dmarBuf, &dmarLen)) && dmarBuf) {
        info.IntelVtdPresent = TRUE;
        if (dmarLen >= sizeof(ACPI_DMAR_HEADER)) {
            PACPI_DMAR_HEADER dmar = (PACPI_DMAR_HEADER)dmarBuf;
            info.DmarHostAddressWidth = dmar->HostAddressWidth;
            info.DmarFlags = dmar->Flags;
            PUCHAR p = (PUCHAR)dmarBuf + sizeof(ACPI_DMAR_HEADER);
            PUCHAR end = (PUCHAR)dmarBuf + dmarLen;
            while (p + sizeof(ACPI_DRHD) <= end) {
                PACPI_DRHD drhd = (PACPI_DRHD)p;
                if (drhd->Type == 0 && drhd->RegisterBaseAddress != 0) {
                    info.DmarRegisterBase = drhd->RegisterBaseAddress;
                    PHYSICAL_ADDRESS pa; pa.QuadPart = (LONGLONG)drhd->RegisterBaseAddress;
                    PVOID vtdRegs = MmMapIoSpace(pa, 0x20, MmNonCached);
                    if (vtdRegs) {
                        __try {
                            info.VtdCapability = *(PULONG64)((PUCHAR)vtdRegs + 0x08);
                            info.VtdExtCapability = *(PULONG64)((PUCHAR)vtdRegs + 0x10);
                            info.GlobalStatusReg = *(PULONG)((PUCHAR)vtdRegs + 0x1C);
                            info.TranslationEnabled = (info.GlobalStatusReg >> 25) & 1;
                            info.RootTableSet = (info.GlobalStatusReg >> 26) & 1;
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER) {}
                        MmUnmapIoSpace(vtdRegs, 0x20);
                    }
                    break;
                }
                if (drhd->Length < 4) break;
                p += drhd->Length;
            }
        }
        GdrvFree(dmarBuf);
    }
    PVOID ivrsBuf = NULL; ULONG ivrsLen = 0;
    if (NT_SUCCESS(GdrvAcpiGetTable(0x53525649, &ivrsBuf, &ivrsLen)) && ivrsBuf) {
        info.AmdIommuPresent = TRUE;
        GdrvFree(ivrsBuf);
    }
    info.WindowsKdmaprot = info.IntelVtdPresent && info.TranslationEnabled;
    __try { ProbeForWrite(userBuf, sizeof(info), sizeof(UCHAR)); RtlCopyMemory(userBuf, &info, sizeof(info)); *written = sizeof(info); return STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}

static NTSTATUS HandleCheckHypervisor(PVOID userBuf, ULONG outLen,
    PULONG_PTR written) {
    if (outLen < sizeof(HYPERVISOR_INFO)) return STATUS_BUFFER_TOO_SMALL;
    HYPERVISOR_INFO info; RtlZeroMemory(&info, sizeof(info));
    int cpu[4];
    __cpuid(cpu, 1);
    info.HypervisorPresent = (cpu[2] >> 31) & 1;
    info.Cr4 = __readcr4();
    ReadMsrSafe(0xC0000082, &info.LstarMsr);
    if (info.HypervisorPresent) {
        __cpuid(cpu, 0x40000000);
        info.HvMaxLeaf = (ULONG)cpu[0];
        RtlCopyMemory(info.VendorString + 0, &cpu[1], 4);
        RtlCopyMemory(info.VendorString + 4, &cpu[2], 4);
        RtlCopyMemory(info.VendorString + 8, &cpu[3], 4);
        info.VendorString[12] = '\0';
        info.IsHyperV = (RtlCompareMemory(info.VendorString, "Microsoft Hv", 12) == 12);
        info.IsVMware = (RtlCompareMemory(info.VendorString, "VMwareVMware", 12) == 12);
        info.IsKvm = (RtlCompareMemory(info.VendorString, "KVMKVMKVM\0\0\0", 12) == 12);
        info.IsXen = (RtlCompareMemory(info.VendorString, "XenVMMXenVMM", 12) == 12);
        info.IsVirtualBox = (RtlCompareMemory(info.VendorString, "VBoxVBoxVBox", 12) == 12);
        if (info.HvMaxLeaf >= 0x40000001) {
            __cpuid(cpu, 0x40000001);
            info.HvInterface = (ULONG)cpu[0];
        }
        if (info.IsHyperV && info.HvMaxLeaf >= 0x40000010) {
            __cpuid(cpu, 0x40000010);
            info.TscFreqKhz = (ULONG64)cpu[0];
        }
    }
    if (g_NtoskrnlBase && g_NtoskrnlSize) {
        if (info.LstarMsr < g_NtoskrnlBase || info.LstarMsr >= g_NtoskrnlBase + g_NtoskrnlSize)
            info.HypervisorPresent = TRUE;
    }
    __try { ProbeForWrite(userBuf, sizeof(info), sizeof(UCHAR)); RtlCopyMemory(userBuf, &info, sizeof(info)); *written = sizeof(info); return STATUS_SUCCESS; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
}

// -----------------------------------------------------------------
// Dispatcher
// -----------------------------------------------------------------
NTSTATUS DeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp) {
    UNREFERENCED_PARAMETER(deviceObject);
    PIO_STACK_LOCATION stk = IoGetCurrentIrpStackLocation(irp);
    ULONG code = stk->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = stk->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = stk->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID inBuf = stk->Parameters.DeviceIoControl.Type3InputBuffer;
    PVOID outBuf = irp->UserBuffer;
    NTSTATUS s = STATUS_UNSUCCESSFUL;
    ULONG_PTR written = 0;

    switch (code) {
    case IOCTL_GDRV_READ_PHYSICAL: {
        if (inLen < sizeof(READ_PHYSICAL_INPUT) || !outBuf) { s = STATUS_BUFFER_TOO_SMALL; break; }
        READ_PHYSICAL_INPUT in;
        __try { ProbeForRead(inBuf, sizeof(in), __alignof(READ_PHYSICAL_INPUT)); in = *(PREAD_PHYSICAL_INPUT)inBuf; }
        __except (EXCEPTION_EXECUTE_HANDLER) { s = STATUS_ACCESS_VIOLATION; break; }
        if (!in.Size || in.Size > MAX_RW_SIZE || in.PhysicalAddress < 0x1000 || outLen < in.Size)
        {
            s = STATUS_INVALID_PARAMETER; break;
        }
        s = ReadPhysicalMemorySafe(outBuf, in.PhysicalAddress, in.Size);
        if (NT_SUCCESS(s)) written = in.Size;
        break;
    }

    case IOCTL_GDRV_READ_VIRTUAL: {
        if (inLen < sizeof(READ_VIRTUAL_INPUT) || !outBuf) { s = STATUS_BUFFER_TOO_SMALL; break; }
        READ_VIRTUAL_INPUT in;
        __try { ProbeForRead(inBuf, sizeof(in), __alignof(READ_VIRTUAL_INPUT)); in = *(PREAD_VIRTUAL_INPUT)inBuf; }
        __except (EXCEPTION_EXECUTE_HANDLER) { s = STATUS_ACCESS_VIOLATION; break; }
        if (!in.Size || in.Size > MAX_RW_SIZE || in.VirtualAddress < 0xFFFF800000000000ULL || outLen < in.Size)
        {
            s = STATUS_INVALID_PARAMETER; break;
        }
        s = ReadVirtualMemorySafe(outBuf, in.VirtualAddress, in.Size);
        if (NT_SUCCESS(s)) written = in.Size;
        break;
    }

    case IOCTL_GDRV_PATTERN_SCAN: {
        if (inLen < sizeof(PATTERN_SCAN_INPUT) || outLen < sizeof(PATTERN_SCAN_OUTPUT) || !outBuf)
        {
            s = STATUS_BUFFER_TOO_SMALL; break;
        }
        PATTERN_SCAN_INPUT in;
        __try { ProbeForRead(inBuf, sizeof(in), __alignof(PATTERN_SCAN_INPUT)); in = *(PPATTERN_SCAN_INPUT)inBuf; }
        __except (EXCEPTION_EXECUTE_HANDLER) { s = STATUS_ACCESS_VIOLATION; break; }
        if (!in.PatternSize || in.PatternSize > MAX_PATTERN_BYTES || !in.SearchSize || in.SearchSize > MAX_SCAN_SIZE || in.SearchBase < 0xFFFF800000000000ULL)
        {
            s = STATUS_INVALID_PARAMETER; break;
        }
        ULONG64 found = ScanKernelPattern(in.SearchBase, in.SearchSize, in.Pattern, in.Mask, in.PatternSize);
        __try { ProbeForWrite(outBuf, sizeof(PATTERN_SCAN_OUTPUT), sizeof(UCHAR)); ((PPATTERN_SCAN_OUTPUT)outBuf)->FoundAddress = found; s = STATUS_SUCCESS; written = sizeof(PATTERN_SCAN_OUTPUT); }
        __except (EXCEPTION_EXECUTE_HANDLER) { s = GetExceptionCode(); }
        break;
    }

    case IOCTL_GDRV_READ_MSR: {
        if (inLen < sizeof(READ_MSR_INPUT) || outLen < sizeof(READ_MSR_OUTPUT) || !outBuf)
        {
            s = STATUS_BUFFER_TOO_SMALL; break;
        }
        READ_MSR_INPUT in;
        __try { ProbeForRead(inBuf, sizeof(in), __alignof(READ_MSR_INPUT)); in = *(PREAD_MSR_INPUT)inBuf; }
        __except (EXCEPTION_EXECUTE_HANDLER) { s = STATUS_ACCESS_VIOLATION; break; }
        ULONG64 val = 0; s = ReadMsrSafe(in.MsrIndex, &val);
        if (NT_SUCCESS(s)) {
            __try { ProbeForWrite(outBuf, sizeof(READ_MSR_OUTPUT), sizeof(UCHAR)); ((PREAD_MSR_OUTPUT)outBuf)->Value = val; written = sizeof(READ_MSR_OUTPUT); }
            __except (EXCEPTION_EXECUTE_HANDLER) { s = GetExceptionCode(); }
        }
        break;
    }

                            // ---- NEW WRITE_MSR ----
    case IOCTL_GDRV_WRITE_MSR: {
        if (inLen < sizeof(WRITE_MSR_INPUT)) {
            s = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        WRITE_MSR_INPUT in;
        __try {
            ProbeForRead(inBuf, sizeof(in), __alignof(WRITE_MSR_INPUT));
            in = *(PWRITE_MSR_INPUT)inBuf;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            s = STATUS_ACCESS_VIOLATION;
            break;
        }
        __try {
            __writemsr(in.MsrIndex, in.Value);
            s = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            s = STATUS_ILLEGAL_INSTRUCTION;
        }
        break;
    }

    case IOCTL_GDRV_GET_PHYS_RANGES:
        if (!outBuf) { s = STATUS_INVALID_USER_BUFFER; break; }
        s = FillPhysicalRanges(outBuf, outLen);
        if (NT_SUCCESS(s)) written = sizeof(PHYS_RANGES_OUTPUT);
        break;

    case IOCTL_GDRV_GET_KERNEL_INFO: {
        if (outLen < sizeof(KERNEL_INFO_OUTPUT) || !outBuf) { s = STATUS_BUFFER_TOO_SMALL; break; }
        KERNEL_INFO_OUTPUT ki;
        ki.NtoskrnlBase = g_NtoskrnlBase;
        ki.NtoskrnlSize = g_NtoskrnlSize;
        ki._Pad = 0;
        ki.PsLoadedModuleListAddr = g_PsLoadedModuleListAddr;
        ki.PsInitialSystemProcessAddr = g_PsInitialSystemProcessAddr;
        ki.KeServiceDescriptorTableAddr = g_KeServiceDescriptorTableAddr;
        ki.KdVersionBlockAddr = g_KdVersionBlockAddr;
        ki.KpcrAddr = __readgsqword(0x18);
        __try { ProbeForWrite(outBuf, sizeof(ki), sizeof(UCHAR)); RtlCopyMemory(outBuf, &ki, sizeof(ki)); s = STATUS_SUCCESS; written = sizeof(ki); }
        __except (EXCEPTION_EXECUTE_HANDLER) { s = GetExceptionCode(); }
        break;
    }

    case IOCTL_GDRV_READ_PCI_CONFIG:
        s = HandleReadPciConfig(inBuf, inLen, outBuf, outLen, &written);
        break;
    case IOCTL_GDRV_SCAN_PCI_BARS:
        if (!outBuf) { s = STATUS_INVALID_USER_BUFFER; break; }
        s = HandleScanPciBars(inBuf, inLen, outBuf, outLen, &written);
        break;
    case IOCTL_GDRV_READ_ACPI_TABLE:
        if (!outBuf) { s = STATUS_INVALID_USER_BUFFER; break; }
        s = HandleReadAcpiTable(inBuf, inLen, outBuf, outLen, &written);
        break;
    case IOCTL_GDRV_CHECK_VMX:
        if (!outBuf) { s = STATUS_INVALID_USER_BUFFER; break; }
        s = HandleCheckVmx(outBuf, outLen, &written);
        break;
    case IOCTL_GDRV_CHECK_SMM:
        if (!outBuf) { s = STATUS_INVALID_USER_BUFFER; break; }
        s = HandleCheckSmm(outBuf, outLen, &written);
        break;
    case IOCTL_GDRV_READ_UEFI_VAR:
        if (!outBuf) { s = STATUS_INVALID_USER_BUFFER; break; }
        s = HandleReadUefiVar(inBuf, inLen, outBuf, outLen, &written);
        break;
    case IOCTL_GDRV_READ_IO_PORT:
        if (!outBuf) { s = STATUS_INVALID_USER_BUFFER; break; }
        s = HandleReadIoPort(inBuf, inLen, outBuf, outLen, &written);
        break;
    case IOCTL_GDRV_ENUMERATE_CALLBACKS:
        if (!outBuf) { s = STATUS_INVALID_USER_BUFFER; break; }
        s = HandleEnumerateCallbacks(inBuf, inLen, outBuf, outLen, &written);
        break;
    case IOCTL_GDRV_DETECT_SSDT_HOOKS:
        if (!outBuf) { s = STATUS_INVALID_USER_BUFFER; break; }
        s = HandleDetectSsdtHooks(outBuf, outLen, &written);
        break;
    case IOCTL_GDRV_READ_KPCR:
        if (!outBuf) { s = STATUS_INVALID_USER_BUFFER; break; }
        s = HandleReadKpcr(outBuf, outLen, &written);
        break;
    case IOCTL_GDRV_SCAN_HIDDEN_DRIVERS:
        if (!outBuf) { s = STATUS_INVALID_USER_BUFFER; break; }
        s = HandleScanHiddenDrivers(inBuf, inLen, outBuf, outLen, &written);
        break;
    case IOCTL_GDRV_CHECK_IOMMU:
        if (!outBuf) { s = STATUS_INVALID_USER_BUFFER; break; }
        s = HandleCheckIommu(outBuf, outLen, &written);
        break;
    case IOCTL_GDRV_CHECK_HYPERVISOR:
        if (!outBuf) { s = STATUS_INVALID_USER_BUFFER; break; }
        s = HandleCheckHypervisor(outBuf, outLen, &written);
        break;

    default:
        s = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Information = written;
    irp->IoStatus.Status = s;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return s;
}

// -----------------------------------------------------------------
// Create/Close/Unload
// -----------------------------------------------------------------
NTSTATUS CreateClose(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT driverObject) {
    UNICODE_STRING sym = RTL_CONSTANT_STRING(L"\\DosDevices\\MyGdrv");
    IoDeleteSymbolicLink(&sym);
    IoDeleteDevice(driverObject->DeviceObject);
}

// -----------------------------------------------------------------
// DriverEntry
// -----------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);

    g_PsLoadedModuleListAddr = ResolveSymbol(L"PsLoadedModuleList");
    g_PsInitialSystemProcessAddr = ResolveSymbol(L"PsInitialSystemProcess");
    g_KeServiceDescriptorTableAddr = ResolveSymbol(L"KeServiceDescriptorTable");
    g_KdVersionBlockAddr = ResolveSymbol(L"KdVersionBlock");

    if (g_PsLoadedModuleListAddr) {
        __try {
            PLIST_ENTRY head = (PLIST_ENTRY)(ULONG_PTR)g_PsLoadedModuleListAddr;
            if (!IsListEmpty(head)) {
                PKLDR_DATA_TABLE_ENTRY_EX e = CONTAINING_RECORD(head->Flink, KLDR_DATA_TABLE_ENTRY_EX, InLoadOrderLinks);
                g_NtoskrnlBase = (ULONG64)e->DllBase;
                g_NtoskrnlSize = e->SizeOfImage;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\MyGdrv");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\MyGdrv");
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    GUID classGuid = { 0 };

    PDEVICE_OBJECT devObj = NULL;
    NTSTATUS s = IoCreateDeviceSecure(driverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &sddl, &classGuid, &devObj);
    if (!NT_SUCCESS(s)) return s;

    s = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(s)) { IoDeleteDevice(devObj); return s; }

    driverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    driverObject->DriverUnload = DriverUnload;

    devObj->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}