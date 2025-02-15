#pragma once
#include <Windows.h>
#include "../native.h"

class Syscall
{
private:
	void* baseAddress = nullptr;
	DWORD idxExportOrder = 0;
	DWORD ssn = 0;

public:
	Syscall() = default;
	Syscall(void* baseAddress,
			const DWORD idxExportOrder,
			const DWORD ssn) :
		baseAddress(baseAddress),
		idxExportOrder(idxExportOrder),
		ssn(ssn)
	{ }

	[[nodiscard]] inline DWORD getSSN() const
	{
		return this->ssn;
	}

	[[nodiscard]] inline void* getBaseAddress() const
	{
		return this->baseAddress;
	}

	void* setBaseAddress(void* addr);
	int setSSN(const int _ssn);
};