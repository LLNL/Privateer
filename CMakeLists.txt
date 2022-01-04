# Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

cmake_minimum_required (VERSION 3.5.1)
project( privateer LANGUAGES CXX C )
set (CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

set (CMAKE_C_STANDARD 17)

set( default_build_type "Release" )
if ( EXISTS "${CMAKE_SOURCE_DIR}/.git" )
  set( default_build_type "Debug" )
endif()

FIND_PACKAGE(OpenSSL)

# option(USE_PAGEMAP_MSYNC ON)

# if (USE_PAGEMAP_MSYNC)
#  add_definitions(-DUSE_PAGEMAP)
# endif()

# if (CRYPTOPP_ROOT)
#  include_directories(${CRYPTOPP_ROOT})
#  link_libraries(${CRYPTOPP_ROOT}/libcryptopp.a)
# else ()
#  message(FATAL_ERROR "Cryptopp850 (https://cryptopp.com/) is required to build Privateer")
# endif ()

# OpenSSL
link_libraries(OpenSSL::SSL)
link_libraries(OpenSSL::Crypto)

# File System
link_libraries(stdc++fs)

# ------------------OpenMP--------------------------
FIND_PACKAGE( OpenMP REQUIRED )

if(OPENMP_FOUND)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
  set(CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
else()
  message(FATAL_ERROR "Error: OpenMP not found")
endif()
# --------------------------------------------------

# ------------------ Boost -------------------------------------------------------------------------------
set (Boost_NO_BOOST_CMAKE ON)

find_package(Boost)

if (Boost_FOUND)

    # Just a sanity check
    if (NOT Boost_INCLUDE_DIRS)
        message(FATAL_ERROR "Something is wrong: Boost_INCLUDE_DIRS is empty although Boost_FOUND is true.")
    endif()
    include_directories(${Boost_INCLUDE_DIRS})
else ()
    message(FATAL_ERROR "Can not find Boost C++ Libraries")
endif ()

# ---------------------------------------------------------------------------------------------------------- 

install(DIRECTORY include/privateer DESTINATION include)

include_directories(include)

find_package(MPI)

add_subdirectory(test_apps)
