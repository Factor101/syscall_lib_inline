#include "SyscallWalker.h"
#include <cstdio>
#ifdef _DEBUG
#include "capstone/capstone.h"
#endif

LIST_ENTRY* SyscallWalker::pModuleListHead = nullptr;
std::map<std::string, Syscall> SyscallWalker::exportSysNumbers;

#define OFFSET(type, field) (uint64_t)(&((type*)nullptr)->field)

void SyscallWalker::init() noexcept
{
    //TODO: this should not be hardcoded OR compile time hashing
    constexpr auto moduleName = L"ntdll.dll";

    SyscallWalker::loadModuleListHead();
    if (const LDR_DATA_TABLE_ENTRY* dllBaseAddress = SyscallWalker::getModuleBaseAddress(moduleName);
        dllBaseAddress != nullptr)
    {
        SyscallWalker::exportSysNumbers = std::map<std::string, Syscall>();
        SyscallWalker::mapDllExports(dllBaseAddress);

    }
    else
    {
        _DEBUG_PRINTF("Failed to find base address of module entry '%ls'\n", moduleName);
    }
}

const LDR_DATA_TABLE_ENTRY* SyscallWalker::getModuleBaseAddress(const wchar_t* moduleName) noexcept
{
    const LDR_DATA_TABLE_ENTRY* pLibraryBase = nullptr;

    for (LIST_ENTRY* node = SyscallWalker::pModuleListHead->Flink;
        node != SyscallWalker::pModuleListHead;
        node = node->Flink)
    {
        // InMemoryOrderLinks = 2nd of 1st 2 entries type LIST_ENTRY
        constexpr auto IN_MEMORY_ORDER_LINKS_OFFSET = sizeof(LIST_ENTRY);
        const LDR_DATA_TABLE_ENTRY* pTableEntry = (LDR_DATA_TABLE_ENTRY*)((uint8_t*)node - IN_MEMORY_ORDER_LINKS_OFFSET); // = CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        _DEBUG_WPRINTF(L"[+] DLL found: %-5ls @ (%5ls)\n",
            pTableEntry->BaseDllName.Buffer,
            pTableEntry->FullDllName.Buffer);
        if (pTableEntry->DllBase == nullptr)
        {
            _DEBUG_PRINTF("[!] DllBase is null\n");
            continue;
        }

        //TODO: Hash dll name
        if (wcscmp(moduleName, pTableEntry->BaseDllName.Buffer) == 0)
        {
            _DEBUG_PRINTF("[+] Found Target DLL\n");
            pLibraryBase = (LDR_DATA_TABLE_ENTRY*)pTableEntry->DllBase;
            break;
        }
    }

    return pLibraryBase;
}


void SyscallWalker::mapDllExports(const LDR_DATA_TABLE_ENTRY* baseAddr) noexcept
{
    const PIMAGE_DOS_HEADER pDosHeader = (const PIMAGE_DOS_HEADER)(const DWORD_PTR)baseAddr;
    const PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)baseAddr + pDosHeader->e_lfanew);
    const DWORD dwExportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    const PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)baseAddr + dwExportDirRVA);

    _DEBUG_PRINTF("[+] DOS Header: 0x%p\n", pDosHeader);
    _DEBUG_PRINTF("[+] NT Header: 0x%p\n", pNtHeaders);
    _DEBUG_PRINTF("[+] Export Directory: 0x%p\n", pExportDir);

    const DWORD* pAddressOfFunctionsRVA = (DWORD*)((DWORD_PTR)baseAddr + pExportDir->AddressOfFunctions);
    const DWORD* pAddressOfNamesRVA = (DWORD*)((DWORD_PTR)baseAddr + pExportDir->AddressOfNames);
    const WORD* pAddressOfNameOrdinalsRVA = (WORD*)((DWORD_PTR)baseAddr + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++)
    {
        // function name
        const DWORD_PTR dwFunctionNameRVA = pAddressOfNamesRVA[i];
        if (dwFunctionNameRVA == 0)
        {
            continue;
        }

        char* pFunctionName = (char*)((DWORD_PTR)baseAddr + dwFunctionNameRVA);
        if (pFunctionName == nullptr)
        {
            continue;
        }

        PVOID pFunctionBase = (PVOID)((DWORD_PTR)baseAddr + pAddressOfFunctionsRVA[pAddressOfNameOrdinalsRVA[i]]);

        // module export function to SyscallWorker::exportSysNumbers
        //TODO: Add runtime hashing for pFunctionName
        SyscallWalker::exportSysNumbers[pFunctionName] = { pFunctionBase, i, 0 };
        _DEBUG_PRINTF("[+] Found Export #%d: \"%s\": 0x%p\n", i, pFunctionName, pFunctionBase);
    }
    _DEBUG_PRINTF("[+] Exported Functions: %d\n", pExportDir->NumberOfFunctions);
}