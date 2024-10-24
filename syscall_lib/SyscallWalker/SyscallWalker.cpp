#include "SyscallWalker.h"

PLIST_ENTRY SyscallWalker::moduleListHead = nullptr;

void SyscallWalker::init() noexcept
{
	SyscallWalker::loadModuleListHead();
}
