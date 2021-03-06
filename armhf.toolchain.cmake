# Inhibit all of CMake's own NDK handling code.
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_NAME Linux-GNU)

message(STATUS "using armhf.toolchain.cmake")

# Allow users to override these values in case they want more strict behaviors.
# For example, they may want to prevent the NDK's libz from being picked up so
# they can use their own.
# https://github.com/android-ndk/ndk/issues/517
if(NOT CMAKE_FIND_ROOT_PATH_MODE_PROGRAM)
  set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
endif()

if(NOT CMAKE_FIND_ROOT_PATH_MODE_LIBRARY)
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
endif()

if(NOT CMAKE_FIND_ROOT_PATH_MODE_INCLUDE)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
endif()

if(NOT CMAKE_FIND_ROOT_PATH_MODE_PACKAGE)
  set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
endif()

set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_C_COMPILER_ID_RUN TRUE)
set(CMAKE_CXX_COMPILER_ID_RUN TRUE)
set(CMAKE_C_COMPILER_ID gcc)
set(CMAKE_CXX_COMPILER_ID gcc)
set(CMAKE_C_COMPILER_VERSION 6.3)
set(CMAKE_CXX_COMPILER_VERSION 6.3)
set(CMAKE_C_STANDARD_COMPUTED_DEFAULT 11)
set(CMAKE_CXX_STANDARD_COMPUTED_DEFAULT 14)

find_program(CMAKE_C_COMPILER NAMES arm-linux-gnueabihf-gcc)
find_program(CMAKE_CXX_COMPILER NAMES arm-linux-gnueabihf-g++)
find_program(CMAKE_LINKER NAMES arm-linux-gnueabihf-ld)
find_program(CMAKE_AR NAMES arm-linux-gnueabihf-ar)

set(CMAKE_CXX_COMPILER ${CMAKE_CXX_COMPILER})
set(CMAKE_C_COMPILER ${CMAKE_C_COMPILER})

set(CMAKE_SIZEOF_VOID_P 4)
