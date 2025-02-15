cmake_minimum_required(VERSION 3.8)

# Add the Syscall source files into the existing syscall_lib target
target_sources(syscall_lib PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/Syscall.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/Syscall.h"
)

target_include_directories(syscall_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)