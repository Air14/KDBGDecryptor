#include "main.h"

// Decoding using KdDecodeDataBlock
#define DECODE_LOUD 0

// Decoding by copying encrypted kdbg struct and then decoding it by using KiWaitNever and KiWaitAlways
#define DECODE_STEALTH 1

ULONG KernelImageSize = 0;
PVOID KernelBase = 0;
PKDDEBUGGER_DATA64 KDGB = 0;
INT64(*KdDecodeDataBlock)();

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT pDrviver, PUNICODE_STRING pRegistry)
{
	UNREFERENCED_PARAMETER(pDrviver);
	UNREFERENCED_PARAMETER(pRegistry);

	pDrviver->DriverUnload = DriverUnload;
	pDrviver->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	pDrviver->MajorFunction[IRP_MJ_CLOSE] = CreateClose;

	do 
	{
		if (GetKDBG(KDGB, DECODE_STEALTH) == FALSE)
		{
			DbgPrint("Couldn't decode kdbg\r\n");
			break;
		}

		DbgPrint("Kernel base address: %p\r\n", KernelBase);
		DbgPrint("Kernel base address from kdbg struct: %p\r\n", KDGB->KernBase);

	} while (FALSE);

	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT pDrviver)
{
	UNREFERENCED_PARAMETER(pDrviver);
}

NTSTATUS CreateClose(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pIrp);
	UNREFERENCED_PARAMETER(pDevice);
	return STATUS_SUCCESS;
}

BOOL GetKernelModule(CHAR* Name, ULONG& ImageSize, PVOID& ImageBase)
{
	ULONG Bytes;
	NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &Bytes);
	PSYSTEM_MODULE_INFORMATION pMods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, Bytes, 'XXXX');

	RtlSecureZeroMemory(pMods, Bytes);

	Status = ZwQuerySystemInformation(SystemModuleInformation, pMods, Bytes, &Bytes);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(pMods, 'XXXX');
		return FALSE;
	}

	PSYSTEM_MODULE_ENTRY pMod = pMods->Modules;
	for (ULONG i = 0; i < pMods->ModulesCount; i++)
	{
		if (strstr((PCSZ)pMod[i].FullPathName, Name) != NULL)
		{
			if (pMod[i].ImageSize != NULL)
			{
				ImageSize = pMod[i].ImageSize;
				ImageBase = pMod[i].ImageBase;
				ExFreePoolWithTag(pMods, 'XXXX');

				return TRUE;
			}
		}

	}

	ExFreePoolWithTag(pMods, 'XXXX');
	return FALSE;
}

BOOL GetKiWaitVariables(PVOID& Kwn, PVOID& Kwa)
{
	UCHAR* KeSetTimerExAddress = (UCHAR*)RtlFindExportedRoutineByName(KernelBase, "KeSetTimerEx");

	// KiWaitNever
	PVOID KiWaitNeverAddress = (KeSetTimerExAddress + 0x1C + 0x7) + (*(UINT32*)(KeSetTimerExAddress + 0x1C + 0x3));

	// KiWaitAlways
	PVOID KiWaitAlwaysAddress = (KeSetTimerExAddress + 0x26 + 0x7) + (*(UINT32*)(KeSetTimerExAddress + 0x26 + 0x3));

	// Check if KiWaitAlways and KiWaitNever are in range of kernel image address space
	if (!(KernelBase < KiWaitAlwaysAddress && KiWaitAlwaysAddress < (UCHAR*)KernelBase + KernelImageSize && KernelBase < KiWaitNeverAddress && KiWaitNeverAddress < (UCHAR*)KernelBase + KernelImageSize))
	{
		return FALSE;
	}

	Kwa = KiWaitAlwaysAddress;
	Kwn = KiWaitNeverAddress;

	return TRUE;
}

VOID DecryptKDBG(PVOID KiWaitNever, PVOID KiWaitAlways, PVOID KdpDataBlockEncodedAddress, PKDDEBUGGER_DATA64& kdbg)
{
	if (*(UCHAR*)KdpDataBlockEncodedAddress)
	{
		for (int i = 0; i < 112; i++)
		{
			*(UINT64*)kdbg = *(UINT64*)KiWaitAlways ^ _byteswap_uint64((UINT64)KdpDataBlockEncodedAddress ^ _rotl64(*(UINT64*)KiWaitNever ^ *(UINT64*)kdbg, *(UCHAR*)KiWaitNever));
			kdbg = (PKDDEBUGGER_DATA64)(((char*)kdbg) + 8);
		}
		kdbg = (PKDDEBUGGER_DATA64)((char*)kdbg - 896);
	}
}

BOOL GetKDBG(PKDDEBUGGER_DATA64& kdbg, UCHAR decodingOption)
{

	if (GetKernelModule("ntoskrnl.exe", KernelImageSize, KernelBase) == FALSE)
	{
		DbgPrint("Couldn't get kernel image base and size\r\n");
		return FALSE;
	}

	UCHAR* KdDecodeDataBlockAddress = (UCHAR*)find_signature(KernelBase, KernelImageSize, "\x48\x83\xEC\x28\x80\x3D\x00\x00\x00\x00\x00\x74\x13\x48\x8D", "xxxxxx?????xxxx");

	PVOID KdDebuggerDataAddress = (*(UINT32*)(KdDecodeDataBlockAddress + 0xD + 0x3)) + (KdDecodeDataBlockAddress + 0xD + 0x7);

	// Check if kdbg is in range of kernel image address space
	if ((UINT64)KdDebuggerDataAddress < (UINT64)KernelBase || (UINT64)KdDebuggerDataAddress > (UINT64)KernelBase + KernelImageSize)
	{
		DbgPrint("KdDebuggerData beyond kernel image address space (some bad calculation happened)\r\n");
		return FALSE;
	}

	// Call KdDecodeDataBlockAddress to decode kdbg. It's encrypted with assist of 2 variables: KiWaitAlways and KiWaitNever
	if (decodingOption == DECODE_LOUD)
	{
		KdDecodeDataBlock = (INT64(*)(void))KdDecodeDataBlockAddress;
		KdDecodeDataBlock();

		kdbg = (PKDDEBUGGER_DATA64)KdDebuggerDataAddress;
	}

	// Copy encrypted kdbg and then decode it
	else
	{
		PVOID KiWaitNever = 0;
		PVOID KiWaitAlways = 0;

		if (GetKiWaitVariables(KiWaitNever, KiWaitAlways) == FALSE)
		{
			return FALSE;
		}

		PVOID KdpDataBlockEncodedAddress = (KdDecodeDataBlockAddress + 0x4 + 0x7) + (*(UINT32*)(KdDecodeDataBlockAddress + 0x4 + 0x2));

		kdbg = (PKDDEBUGGER_DATA64)ExAllocatePoolWithTag(NonPagedPool, sizeof(KDDEBUGGER_DATA64), 'XXXX');

		RtlZeroMemory(kdbg, sizeof(KDDEBUGGER_DATA64));
		RtlCopyMemory(kdbg, KdDebuggerDataAddress, sizeof(KDDEBUGGER_DATA64));

		DecryptKDBG(KiWaitNever, KiWaitAlways, KdpDataBlockEncodedAddress, kdbg);
	}

	// Check if kdbg KerenelBase is equal base address of kernel image
	if ((PVOID)kdbg->KernBase != KernelBase)
	{
		DbgPrint("KdDebuggerData unencrypted or bad calculation happened\r\n");
		return FALSE;
	}

	return TRUE;
}

void* find_signature(void* memory, size_t size, const char* pattern, const char* mask)
{
	size_t sig_length = strlen(mask);
	if (sig_length > size) return nullptr;

	for (size_t i = 0; i < size - sig_length; i++)
	{
		bool found = true;
		for (size_t j = 0; j < sig_length; j++)
			found &= mask[j] == '?' || pattern[j] == *((char*)memory + i + j);

		if (found)
			return (char*)memory + i;
	}
	return nullptr;
}