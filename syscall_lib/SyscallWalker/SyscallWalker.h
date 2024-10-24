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
	static PLIST_ENTRY moduleListHead;

	__forceinline static void loadModuleListHead() noexcept
	{
		const PEB* peb = (PEB*)__readgsqword(0x60);
		PEB_LDR_DATA* pebLdrData = peb->Ldr;
#ifdef _DEBUG
		printf("[+] PEB Address: 0x%p\n", peb);
		printf("[+] PEB_LDR_DATA Address: 0x%p\n", pebLdrData);
		printf("[+] InMemoryOrderModuleList Address: 0x%p\n", &pebLdrData->InMemoryOrderModuleList);
#endif

		moduleListHead = &pebLdrData->InMemoryOrderModuleList;
	}

public:
	static void init() noexcept;
};