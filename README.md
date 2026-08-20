# MyGdrv – Kernel Memory Reader Driver

**MyGdrv** is a minimal, stable Windows kernel driver (WDM) that exposes IOCTLs for reading physical and virtual memory from ring‑3. It is built for educational and forensic purposes – to enable a user‑mode scanner to inspect kernel structures (SSDT, process lists, callbacks, UEFI tables, etc.) without relying on vulnerable third‑party drivers.

> **⚠️ Important:** This driver is **not** a rootkit or hacking tool. It is read‑only and does not modify kernel memory. It is intended for **legitimate system analysis and security research** on systems you own or are authorised to test.

---

## Features

- **Physical memory read** – map and read arbitrary physical addresses.
- **Virtual memory read** – directly read kernel virtual addresses (bypasses HVCI when loaded as a service).
- **Pattern scanning** – search kernel memory for byte sequences with wildcards (find unexported symbols).
- **MSR read** – safely read model‑specific registers.
- **Physical memory range enumeration** – get the system’s physical memory map.
- **Kernel info query** – obtain ntoskrnl base, `PsLoadedModuleList`, `PsInitialSystemProcess`, `KeServiceDescriptorTable`, `KdVersionBlock`, and current `KPCR`.
- **Secure** – device restricted to `SYSTEM` and `Administrators` (SDDL).
- **Resilient** – uses structured exception handling to avoid BSODs on invalid accesses.

---

## Requirements

- **Windows 10/11 x64** (tested on 20H2 – 22H2).
- **Administrator privileges** to load the driver.
- **Test‑signing enabled** (since the driver is not signed with a Microsoft certificate) – run as Admin:
  ```cmd
  bcdedit /set testsigning on
  bcdedit /set nointegritychecks on
  reboot
