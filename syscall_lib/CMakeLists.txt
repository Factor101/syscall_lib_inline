# CMakeList.txt : CMake project for syscall_lib, include source and define
# project specific logic here.
#
cmake_minimum_required(VERSION 3.8)
project(syscall_lib)
set(ENV{PKG_CONFIG_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/../include/capstone/lib/pkgconfig;$ENV{PKG_CONFIG_PATH}")

include(FindPkgConfig)
pkg_check_modules(CAPSTONE REQUIRED capstone)

message(STATUS "CAPSTONE_LIBRARIES: ${CAPSTONE_LIBRARIES}")
message(STATUS "CAPSTONE_INCLUDE_DIRS: ${CAPSTONE_INCLUDE_DIRS}")

add_executable(syscall_lib
    "syscall_lib.cpp"
)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET syscall_lib PROPERTY CXX_STANDARD 23)
endif()

# TODO: Add tests and install targets if needed.
# Add subdirectories for Syscall and SyscallWalker
add_subdirectory(Syscall)
add_subdirectory(SyscallWalker)

# Optionally set include directories for this library
target_include_directories(syscall_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CAPSTONE_INCLUDE_DIRS}
)

target_link_directories(syscall_lib PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../include/capstone/lib")
target_link_libraries(syscall_lib PRIVATE ${CAPSTONE_LIBRARIES})
