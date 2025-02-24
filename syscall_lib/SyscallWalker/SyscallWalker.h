// ReSharper disable CppClangTidyClangDiagnosticGnuZeroVariadicMacroArguments
#pragma once
#include <Windows.h>
#include "../native.h"
#include <map>
#include <intrin.h>
#include <cstdio>
#include <string>

#include "../Syscall/Syscall.h"
#define _DEBUG 1
#ifdef _DEBUG
#define _DEBUG_PRINTF(format, ...) printf(format, ##__VA_ARGS__)
#define _DEBUG_WPRINTF(format, ...) wprintf(format, ##__VA_ARGS__)
#else
	#define _DEBUG_PRINTF(format, ...) ((void)0)
	#define _DEBUG_WPRINTF(format, ...) ((void)0)
#endif

class SyscallWalker
{
private:
	static std::map<std::string, Syscall> exportSysNumbers;
	static LIST_ENTRY* pModuleListHead;

	static const LDR_DATA_TABLE_ENTRY* getModuleEntry(const wchar_t* moduleName) noexcept;
	static void mapExports(const LDR_DATA_TABLE_ENTRY* baseAddr) noexcept;

	__forceinline static void loadModuleListHead() noexcept
	{
		PEB* peb;
		asm
		(
			"mov %[ppeb], gs:[0x60]"
			: [ppeb] "=r"(peb)
		);
		
		PEB_LDR_DATA* pebLdrData = peb->Ldr;
		PEB_LDR_DATA* foo = (PEB_LDR_DATA*)((DWORD*)peb + 104);
		SyscallWalker::pModuleListHead = &pebLdrData->InMemoryOrderModuleList;

		_DEBUG_PRINTF("[+] PEB Address: 0x%p\n", peb);
		_DEBUG_PRINTF("[+] PEB_LDR_DATA Address: 0x%p\n", foo);
		_DEBUG_PRINTF("[+] PEB_LDR_DATA Address2: 0x%p\n", pebLdrData);
		_DEBUG_PRINTF("[+] InMemoryOrderModuleList Address: 0x%p\n", &pebLdrData->InMemoryOrderModuleList);
	}

public:
	static void init() noexcept;
};