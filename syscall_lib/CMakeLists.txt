# CMakeList.txt : CMake project for syscall_lib, include source and define
# project specific logic here.
#
cmake_minimum_required(VERSION 3.8)

# Create a library from the sources in the syscall_lib folder
add_executable(syscall_lib
    "syscall_lib.cpp"
    #"syscall_lib.h"
    #"native.h"
)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET syscall_lib PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
# Add subdirectories for Syscall and SyscallWalker
add_subdirectory(Syscall)
add_subdirectory(SyscallWalker)

# Optionally set include directories for this library
target_include_directories(syscall_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(syscall_lib PRIVATE
    capstone
)