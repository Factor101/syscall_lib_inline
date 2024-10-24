#pragma once
#include <Windows.h>
#include "../native.h"
#include <string>
#include <cstdint>
#include <map>
#include <intrin.h>
#define _DEBUG 1

class SyscallWalker
{
private:
	static const std::map<std::string, DWORD> exportSysNumbers;
	static LIST_ENTRY* moduleListHead;

	static LDR_DATA_TABLE_ENTRY* getModuleEntry(const std::string& moduleName) noexcept;


	__forceinline static void loadModuleListHead() noexcept
	{
		PEB* peb;
		asm (
			"mov %[ppeb], qword ptr gs:[0x60]"
			: [ppeb] "=r"(peb)
		);

		PEB_LDR_DATA* pebLdrData = peb->Ldr;
#ifdef _DEBUG
		printf("[+] PEB Address: 0x%p\n", peb);
		printf("[+] PEB_LDR_DATA Address: 0x%p\n", pebLdrData);
		printf("[+] InMemoryOrderModuleList Address: 0x%p\n", &pebLdrData->InMemoryOrderModuleList);
#endif

		SyscallWalker::moduleListHead = &pebLdrData->InMemoryOrderModuleList;
	}

public:
	static void init() noexcept;
};