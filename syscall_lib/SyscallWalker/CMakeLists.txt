cmake_minimum_required(VERSION 3.8)

target_sources(syscall_lib PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/SyscallWalker.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/SyscallWalker.h"
)

target_include_directories(syscall_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)