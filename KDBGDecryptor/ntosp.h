#pragma once
#include <ntddk.h>

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemExtendedProcessInformation = 6,
    SystemProcessorPerformanceInformation = 8,
    SystemModuleInformation = 11,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemFullProcessInformation = 148
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE {
    PVOID 	Reserved1;
    PVOID 	Reserved2;
    PVOID 	ImageBaseAddress;
    ULONG 	ImageSize;
    ULONG 	Flags;
    unsigned short 	Id;
    unsigned short 	Rank;
    unsigned short 	Unknown;
    unsigned short 	NameOffset;
    unsigned char 	Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG                       ModulesCount;
    SYSTEM_MODULE_ENTRY         Modules[1];
    ULONG                       Count;
    SYSTEM_MODULE 	            Sys_Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct DBGKD_DEBUG_DATA_HEADER64 {
    struct LIST_ENTRY64 {
        struct LIST_ENTRY64* Flink;
        struct LIST_ENTRY64* Blink;
    } List;
    UINT32           OwnerTag;
    UINT32           Size;
} DBGKD_DEBUG_DATA_HEADER64;

typedef struct KDDEBUGGER_DATA64 {
    DBGKD_DEBUG_DATA_HEADER64 Header;

    UINT64 KernBase;
    UINT64 BreakpointWithStatus;
    UINT64 SavedContext;
    UINT16 ThCallbackStack;
    UINT16 NextCallback;
    UINT16 FramePointer;
    UINT16 PaeEnabled : 1;
    UINT64 KiCallUserMode;
    UINT64 KeUserCallbackDispatcher;
    UINT64 PsLoadedModuleList;
    UINT64 PsActiveProcessHead;
    UINT64 PspCidTable;
    UINT64 ExpSystemResourcesList;
    UINT64 ExpPagedPoolDescriptor;
    UINT64 ExpNumberOfPagedPools;
    UINT64 KeTimeIncrement;
    UINT64 KeBugCheckCallbackListHead;
    UINT64 KiBugcheckData;
    UINT64 IopErrorLogListHead;
    UINT64 ObpRootDirectoryObject;
    UINT64 ObpTypeObjectType;
    UINT64 MmSystemCacheStart;
    UINT64 MmSystemCacheEnd;
    UINT64 MmSystemCacheWs;
    UINT64 MmPfnDatabase;
    UINT64 MmSystemPtesStart;
    UINT64 MmSystemPtesEnd;
    UINT64 MmSubsectionBase;
    UINT64 MmNumberOfPagingFiles;
    UINT64 MmLowestPhysicalPage;
    UINT64 MmHighestPhysicalPage;
    UINT64 MmNumberOfPhysicalPages;
    UINT64 MmMaximumNonPagedPoolInBytes;
    UINT64 MmNonPagedSystemStart;
    UINT64 MmNonPagedPoolStart;
    UINT64 MmNonPagedPoolEnd;
    UINT64 MmPagedPoolStart;
    UINT64 MmPagedPoolEnd;
    UINT64 MmPagedPoolInformation;
    UINT64 MmPageSize;
    UINT64 MmSizeOfPagedPoolInBytes;
    UINT64 MmTotalCommitLimit;
    UINT64 MmTotalCommittedPages;
    UINT64 MmSharedCommit;
    UINT64 MmDriverCommit;
    UINT64 MmProcessCommit;
    UINT64 MmPagedPoolCommit;
    UINT64 MmExtendedCommit;
    UINT64 MmZeroedPageListHead;
    UINT64 MmFreePageListHead;
    UINT64 MmStandbyPageListHead;
    UINT64 MmModifiedPageListHead;
    UINT64 MmModifiedNoWritePageListHead;
    UINT64 MmAvailablePages;
    UINT64 MmResidentAvailablePages;
    UINT64 PoolTrackTable;
    UINT64 NonPagedPoolDescriptor;
    UINT64 MmHighestUserAddress;
    UINT64 MmSystemRangeStart;
    UINT64 MmUserProbeAddress;
    UINT64 KdPrintCircularBuffer;
    UINT64 KdPrintCircularBufferEnd;
    UINT64 KdPrintWritePointer;
    UINT64 KdPrintRolloverCount;
    UINT64 MmLoadedUserImageList;

    /* NT 5.1 Addition */

    UINT64 NtBuildLab;
    UINT64 KiNormalSystemCall;

    /* NT 5.0 hotfix addition */

    UINT64 KiProcessorBlock;
    UINT64 MmUnloadedDrivers;
    UINT64 MmLastUnloadedDriver;
    UINT64 MmTriageActionTaken;
    UINT64 MmSpecialPoolTag;
    UINT64 KernelVerifier;
    UINT64 MmVerifierData;
    UINT64 MmAllocatedNonPagedPool;
    UINT64 MmPeakCommitment;
    UINT64 MmTotalCommitLimitMaximum;
    UINT64 CmNtCSDVersion;

    /* NT 5.1 Addition */

    UINT64 MmPhysicalMemoryBlock;
    UINT64 MmSessionBase;
    UINT64 MmSessionSize;
    UINT64 MmSystemParentTablePage;

    /* Server 2003 addition */

    UINT64 MmVirtualTranslationBase;
    UINT16 OffsetKThreadNextProcessor;
    UINT16 OffsetKThreadTeb;
    UINT16 OffsetKThreadKernelStack;
    UINT16 OffsetKThreadInitialStack;
    UINT16 OffsetKThreadApcProcess;
    UINT16 OffsetKThreadState;
    UINT16 OffsetKThreadBStore;
    UINT16 OffsetKThreadBStoreLimit;
    UINT16 SizeEProcess;
    UINT16 OffsetEprocessPeb;
    UINT16 OffsetEprocessParentCID;
    UINT16 OffsetEprocessDirectoryTableBase;
    UINT16 SizePrcb;
    UINT16 OffsetPrcbDpcRoutine;
    UINT16 OffsetPrcbCurrentThread;
    UINT16 OffsetPrcbMhz;
    UINT16 OffsetPrcbCpuType;
    UINT16 OffsetPrcbVendorString;
    UINT16 OffsetPrcbProcStateContext;
    UINT16 OffsetPrcbNumber;
    UINT16 SizeEThread;
    UINT64 KdPrintCircularBufferPtr;
    UINT64 KdPrintBufferSize;
    UINT64 KeLoaderBlock;
    UINT16 SizePcr;
    UINT16 OffsetPcrSelfPcr;
    UINT16 OffsetPcrCurrentPrcb;
    UINT16 OffsetPcrContainedPrcb;
    UINT16 OffsetPcrInitialBStore;
    UINT16 OffsetPcrBStoreLimit;
    UINT16 OffsetPcrInitialStack;
    UINT16 OffsetPcrStackLimit;
    UINT16 OffsetPrcbPcrPage;
    UINT16 OffsetPrcbProcStateSpecialReg;
    UINT16 GdtR0Code;
    UINT16 GdtR0Data;
    UINT16 GdtR0Pcr;
    UINT16 GdtR3Code;
    UINT16 GdtR3Data;
    UINT16 GdtR3Teb;
    UINT16 GdtLdt;
    UINT16 GdtTss;
    UINT16 Gdt64R3CmCode;
    UINT16 Gdt64R3CmTeb;
    UINT64 IopNumTriageDumpDataBlocks;
    UINT64 IopTriageDumpDataBlocks;

    /* Longhorn addition */

    UINT64 VfCrashDataBlock;
    UINT64 MmBadPagesDetected;
    UINT64 MmZeroedPageSingleBitErrorsDetected;

    /* Windows 7 addition */

    UINT64 EtwpDebuggerData;
    UINT16 OffsetPrcbContext;
    UCHAR PAD[0x40];
} KDDEBUGGER_DATA64, *PKDDEBUGGER_DATA64;

extern "C"
NTKERNELAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

extern "C"
NTKERNELAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID ImageBase,
    _In_ PCCH RoutineNam
);