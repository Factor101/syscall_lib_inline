#include "SyscallWalker.h"

LIST_ENTRY* SyscallWalker::moduleListHead = nullptr;

LDR_DATA_TABLE_ENTRY* SyscallWalker::getModuleEntry(const std::string& moduleName) noexcept
{
	LDR_DATA_TABLE_ENTRY* pLibraryBase = nullptr;

	for (LIST_ENTRY* node = SyscallWalker::moduleListHead->Flink; node != SyscallWalker::moduleListHead; node = node->Flink)
	{
		constexpr int IN_MEMORY_ORDER_LINKS_OFFSET = sizeof(LIST_ENTRY);
		LDR_DATA_TABLE_ENTRY* pTableEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)node - IN_MEMORY_ORDER_LINKS_OFFSET);
		wprintf(L"[+] DLL found: %-5s @ (%5s)\n", pTableEntry->BaseDllName.Buffer, pTableEntry->FullDllName.Buffer);

		if (pTableEntry->DllBase == nullptr)
		{
			printf("[!] DllBase is null\n");
			continue;
		}

		//TODO: Hash dll name
		if (wcscmp(name, pTableEntry->BaseDllName.Buffer) == 0)
		{
#ifdef _DEBUG
			printf("[+] Found Target DLL\n");
#endif
			pLibraryBase = pTableEntry->DllBase;
			break;
		}
	}

	return pLibraryBase;
}

void SyscallWalker::init() noexcept
{
	SyscallWalker::loadModuleListHead();
}
