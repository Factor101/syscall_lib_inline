# CMakeList.txt : CMake project for syscall_lib, include source and define
# project specific logic here.
#

# Add source to this project's executable.
add_executable (syscall_lib "syscall_lib.cpp" "syscall_lib.h" "SyscallWalker/SyscallWalker.cpp" "SyscallWalker/SyscallWalker.h" "native.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET syscall_lib PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
