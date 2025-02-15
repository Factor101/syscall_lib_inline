#include "SyscallWalker.h"
#include <cinttypes>
#include <cstdio>
#include "capstone/capstone.h"

LIST_ENTRY* SyscallWalker::pModuleListHead = nullptr;
std::map<std::string, Syscall> SyscallWalker::exportSysNumbers;

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
		SyscallWalker::exportSysNumbers = std::map<std::string, Syscall>();
		SyscallWalker::mapExports(dllBaseAddress);



		// find NtOpenFile
		std::string targetFunction = "NtOpenFile";
		auto it = SyscallWalker::exportSysNumbers.find(targetFunction);
		uint8_t CODE[0x30] = { 0 };

		if (it != SyscallWalker::exportSysNumbers.end())
		{
			Syscall syscall = it->second;
			memcpy(CODE, (PBYTE)syscall.getBaseAddress(), 0x30);
			printf("[+] Found %s: 0x%p\n", targetFunction.c_str(), syscall.getBaseAddress());
		}
		else
		{
			printf("[!] Failed to find %s\n", targetFunction.c_str());
			// print all exports
			for (const auto& pair : SyscallWalker::exportSysNumbers)
			{
				printf("[+] '%s': 0x%p\n", pair.first.c_str(), pair.second.getBaseAddress());
			}
		}



		for (int i = 0; i < 0x30; i++)
		{
			//PBYTE pCurrentByte = (PBYTE)sys.getBaseAddress() + i;
			
		}


		csh handle;
		cs_insn* insn;

		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
			printf("ERROR: Failed to initialize cs engine!\n");
		// now only search first 30 bytes
		size_t count = cs_disasm(handle, CODE, 0x30, 0x0, 30, &insn);
		/*size_t count = cs_disasm(handle, CODE, sizeof(CODE) - 1, 0x0, 0, &insn);*/
		if (count > 0) {
			for (size_t j = 0; j < count; j++) {
				printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
			}

			cs_free(insn, count);
		}
		else
			printf("ERROR: Failed to disassemble given code!\n");

		cs_close(&handle);



	}
	else
	{
#ifdef _DEBUG
		printf("Failed to find base address of module entry '%ls'\n", moduleName);
#endif
	}
}
