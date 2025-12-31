//By AlSch092 @ Github
#pragma once
#include <ImageHlp.h>
#include <Psapi.h>
#include <vector>
#include <string>

#pragma comment(lib, "ImageHlp")

struct MODULE_DATA
{
	std::wstring baseName;
	std::wstring nameWithPath;
	MODULEINFO dllInfo;
	HMODULE hModule = 0;
};

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct MY_PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	PVOID ShutdownThreadId;
} MY_PEB_LDR_DATA, * MY_PPEB_LDR_DATA;

typedef enum _LDR_DLL_LOAD_REASON
{
	LoadReasonStaticDependency,
	LoadReasonStaticLoad,
	LoadReasonDynamicLoad,
	LoadReasonAsImageLoad,
	LoadReasonAsDataLoad,
	LoadReasonEnclavePrimary,
	LoadReasonEnclaveDependency,
	LoadReasonPatchImage,
	LoadReasonUnknownReason = -1
} LDR_DLL_LOAD_REASON;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	// Windows 10 specific fields
	PVOID LoadedImports;
	PVOID EntryPointActivationContext; // Since Windows 10 1607 (Anniversary Update)
	PVOID PatchInformation;
	LDR_DLL_LOAD_REASON LoadReason;
} MY_LDR_DATA_TABLE_ENTRY, * MY_PLDR_DATA_TABLE_ENTRY;

typedef struct _MYPEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	MY_PEB_LDR_DATA* Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID FastPebLockRoutine;
	PVOID FastPebUnlockRoutine;
	ULONG EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID EventLogSection;
	PVOID EventLog;
	PVOID FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[0x2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	UCHAR Spare2[0x4];
	ULARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper; //PPS_POST_PREOCESS_INIT_ROUTINE?
	PVOID GdiDCAttributeList;
	PVOID LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	ULONG OSBuildNumber;
	ULONG OSPlatformId;
	ULONG ImageSubSystem;
	ULONG ImageSubSystemMajorVersion;
	ULONG ImageSubSystemMinorVersion;
	ULONG GdiHandleBuffer[0x22];
	PVOID ProcessWindowStation;
} MYPEB, * PMYPEB;

inline int GetStrLength(__in const LPSTR str)
{
	if (str == nullptr)
		return 0;

	int len = 0;
	while (true)
	{
		if (str[len] == 0)
			break;

		len++;
	}

	return len;
}

inline int GetStrLengthW(__in const LPWSTR str)
{
	if (str == nullptr)
		return 0;

	int len = 0;
	while (true)
	{
		if (str[len] == 0 && str[len + 1] == 0)
			break;

		len++;
	}

	return len;
}

inline bool StrCmp(__in const char* str1, __in const char* str2)
{
	if (str1 == nullptr || str2 == nullptr)
		return false;

	int count = 0;
	char ch = str1[count];

	while (ch != NULL)
	{
		char ch2 = str2[count];

		if (ch != ch2)
			return false;

		count++;
		ch = str1[count];
	}

	return true;
}

inline void _memcpy(__inout void* dest, __in const void* src, __in size_t size)
{
	if (dest == nullptr || src == nullptr || size == 0)
		return;

	byte* byteDest = (byte*)dest;
	byte* byteSrc = (byte*)src;
	for (size_t i = 0; i < size; i++)
	{
		byteDest[i] = byteSrc[i];
	}
}


/*
	API-less conversion from multibyte string to wide char string
	Assumes zero other APIs are available, and only limited space is given
	** Not recommended for general use -> we are only using it for converting DLL names in _GetProcAddress **
*/
inline wchar_t* mbtowc(const char* mbstr)
{
	if (mbstr == nullptr)
		return nullptr;

	int len = GetStrLength((LPSTR)mbstr);

	wchar_t wstr[256]{ 0 };

	for (int i = 0; i < len; i++) //will only work for english ascii, but shouldnt be a problem for the use of dll names
	{
		wstr[i] = (wchar_t)mbstr[i];
	}

	return wstr;
}

/*
	_GetModuleHandle - Substituion for GetModuleHandleA/W for when we don't know the address of WINAPIs
	Useful for shellcode, EPT hooks, etc
	returns nullptr on failure
*/
inline HMODULE _GetModuleHandle(__in const LPWSTR mod)
{
	if (mod == nullptr)
		return (HMODULE)NULL;

#ifdef _M_IX86
	MYPEB* peb = (MYPEB*)__readfsdword(0x30);
#else
	MYPEB* peb = (MYPEB*)__readgsqword(0x60);
#endif

	uintptr_t kernel32Base = 0;

	LIST_ENTRY* current_record = NULL;
	LIST_ENTRY* start = &(peb->Ldr->InLoadOrderModuleList);

	current_record = start->Flink;

	int modLen = GetStrLengthW(mod);

	while (true)
	{
		MY_LDR_DATA_TABLE_ENTRY* module_entry = (MY_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(current_record, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		for (int i = 0; i < modLen; i++)
		{
			if (mod[i] != module_entry->BaseDllName.Buffer[i])
				break;

			if (i == modLen - 1)
			{
				return (HMODULE)module_entry->DllBase;
			}
		}

		current_record = current_record->Flink;

		if (current_record == start)
		{
			break;
		}
	}

	return 0;
}

/*
	_GetProcAddress - Attempt to retrieve address of function `lpFuncName` from `Module`
	Used for dynamic API lookups in scenarios where we don't know the address of GetProcAddress or any other info beforehand
	For example, we can use this in EPT hooks where a page allocated in Process A becomes the new code page for Process B, and we need to use WINAPIs
	... We cannot just call GetProcAddress because of relocations/ASLR/offsets being different in Process B
*/
inline FARPROC _GetProcAddress(__in const wchar_t* ModuleName, __in const char* lpFuncName)
{
	if (!ModuleName || !lpFuncName)
		return nullptr;

	HMODULE hMod = _GetModuleHandle((const LPWSTR)ModuleName);

	if (!hMod)
		return nullptr;

	auto base = reinterpret_cast<uint8_t*>(hMod);

	auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);

	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);

	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (!dir.VirtualAddress || !dir.Size)
		return nullptr;

	auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + dir.VirtualAddress);

	auto names = reinterpret_cast<DWORD*>(base + exports->AddressOfNames);
	auto ordinals = reinterpret_cast<WORD*>(base + exports->AddressOfNameOrdinals);
	auto functions = reinterpret_cast<DWORD*>(base + exports->AddressOfFunctions);

	for (DWORD i = 0; i < exports->NumberOfNames; i++)
	{
		const char* name = reinterpret_cast<const char*>(base + names[i]);

		if (StrCmp(name, lpFuncName))
		{
			DWORD rva = functions[ordinals[i]];

			// Handle forwarded exports -> TODO: Finish this some time
			//if (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size)
			//{
			//	const char* forwarder = reinterpret_cast<const char*>(base + rva);

			//	//ex: "KERNEL32.Sleep"
			//	char fwdMod[256]{};
			//	char fwdFunc[256]{};
			//	 
			//	const char* dot = strchr(forwarder, '.'); //TODO: Make API-less, standalone functions to mimic this call
			//	if (!dot)
			//		return nullptr;

			//	strncpy_s(fwdMod, forwarder, dot - forwarder); //TODO: Make API-less, standalone functions to mimic this call
			//	strcat_s(fwdMod, ".dll"); //TODO: Make API-less, standalone functions to mimic this call
			//	strcpy_s(fwdFunc, dot + 1); //TODO: Make API-less, standalone functions to mimic this call

			//	wchar_t* wMod = mbtowc(fwdMod);
			//	
			//	return _GetProcAddress(wMod, fwdFunc);
			//}

			return reinterpret_cast<FARPROC>(base + rva);
		}
	}

	return nullptr;
}
