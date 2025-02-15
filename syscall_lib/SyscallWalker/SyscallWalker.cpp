#include "SyscallWalker.h"
#include "capstone.h"

LIST_ENTRY* SyscallWalker::pModuleListHead = nullptr;
std::map<char*, Syscall> SyscallWalker::exportSysNumbers;

const LDR_DATA_TABLE_ENTRY* SyscallWalker::getModuleEntry(const wchar_t* moduleName) noexcept
{
	const LDR_DATA_TABLE_ENTRY* pLibraryBase = nullptr;

	for(LIST_ENTRY* node = SyscallWalker::pModuleListHead->Flink->Flink;
		node != SyscallWalker::pModuleListHead;
		node = node->Flink)
	{
		constexpr int IN_MEMORY_ORDER_LINKS_OFFSET = sizeof(LIST_ENTRY);
		const LDR_DATA_TABLE_ENTRY* pTableEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)node - IN_MEMORY_ORDER_LINKS_OFFSET);

#ifdef _DEBUG
		wprintf(L"[+] DLL found: %-5ls @ (%5ls)\n", pTableEntry->BaseDllName.Buffer, pTableEntry->FullDllName.Buffer);
#endif
		if(pTableEntry->DllBase == nullptr)
		{
#ifdef _DEBUG
			printf("[!] DllBase is null\n");
#endif
			continue;
		}

		//TODO: Hash dll name
		if(wcscmp(moduleName, pTableEntry->BaseDllName.Buffer) == 0)
		{
#ifdef _DEBUG
			printf("[+] Found Target DLL\n");
#endif
			pLibraryBase = (LDR_DATA_TABLE_ENTRY*)pTableEntry->DllBase;
			break;
		}
	}

	return pLibraryBase;
}


void SyscallWalker::mapExports(const LDR_DATA_TABLE_ENTRY* baseAddr) noexcept
{
	const LPVOID pBaseAddr = (LPVOID)baseAddr;
	const PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddr;
	const PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)baseAddr + pDosHeader->e_lfanew);
	const DWORD dwExportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)baseAddr + dwExportDirRVA);

#ifdef _DEBUG
	printf("[+] DOS Header: 0x%p\n", pDosHeader);
	printf("[+] NT Header: 0x%p\n", pNtHeaders);
	printf("[+] Export Directory: 0x%p\n", pExportDir);
#endif

	const DWORD* pAddressOfFunctionsRVA = (DWORD*)((DWORD_PTR)baseAddr + pExportDir->AddressOfFunctions);
	const DWORD* pAddressOfNamesRVA = (DWORD*)((DWORD_PTR)baseAddr + pExportDir->AddressOfNames);
	const WORD* pAddressOfNameOrdinalsRVA = (WORD*)((DWORD_PTR)baseAddr + pExportDir->AddressOfNameOrdinals);

	for(DWORD i = 0; i < pExportDir->NumberOfFunctions; i++)
	{
		// function name
		const DWORD_PTR dwFunctionNameRVA = pAddressOfNamesRVA[i];
		if(dwFunctionNameRVA == 0)
		{
			continue;
		}

		char* pFunctionName = (char*)((DWORD_PTR)baseAddr + dwFunctionNameRVA);
		if(pFunctionName == nullptr)
		{
			continue;
		}

		PVOID pFunctionBase = (PVOID)((DWORD_PTR)baseAddr + pAddressOfFunctionsRVA[pAddressOfNameOrdinalsRVA[i]]);

		// module export function to SyscallWorker::exportSysNumbers
		//TODO: Add runtime hashing for pFunctionName
		SyscallWalker::exportSysNumbers[pFunctionName] = { pFunctionBase, i, 0 };
#ifdef _DEBUG
		printf("[+] Found Export \"%s\": 0x%p\n", pFunctionName, pFunctionBase);
#endif

	}
}


void SyscallWalker::init() noexcept
{
	//TODO: this should not be hardcoded OR compile time hashing
	constexpr auto moduleName = L"ntdll.dll";

	SyscallWalker::loadModuleListHead();
	const LDR_DATA_TABLE_ENTRY* dllBaseAddress = SyscallWalker::getModuleEntry(moduleName);
	if(dllBaseAddress != nullptr)
	{
		SyscallWalker::exportSysNumbers = std::map<char*, Syscall>();
		SyscallWalker::mapExports(dllBaseAddress);
	}
	else
	{
#ifdef _DEBUG
		printf("Failed to find base address of module entry '%ls'\n", moduleName);
#endif
	}
}
