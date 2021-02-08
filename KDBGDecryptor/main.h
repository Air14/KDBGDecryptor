#pragma once
#include <ntddk.h>
#include <minwindef.h>
#include "ntosp.h"


BOOL GetKernelModule(CHAR* Name, ULONG& ImageSize, PVOID& ImageBase);

BOOL GetKiWaitVariables(PVOID& kwn, PVOID& kwa);

BOOL GetKDBG(PKDDEBUGGER_DATA64 &kdbg, UCHAR decodingOption);

NTSTATUS CreateClose(PDEVICE_OBJECT pDevice, PIRP irp);

VOID DecryptKDBG(PVOID KiWaitNever, PVOID KiWaitAlways, PVOID KdpDataBlockEncodedAddress, PKDDEBUGGER_DATA64& kdbg);

VOID DriverUnload(PDRIVER_OBJECT pDrviver);

void* find_signature(void* memory, size_t size, const char* pattern, const char* mask);