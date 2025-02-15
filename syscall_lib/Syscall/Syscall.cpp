#include "Syscall.h"

void* Syscall::setBaseAddress(void* addr)
{
	this->baseAddress = addr;
	return addr;
}

int Syscall::setSSN(const int _ssn)
{
	this->ssn = _ssn;
	return _ssn;
}
