# Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

project(random_sparse_update)

FIND_PACKAGE( OpenMP REQUIRED )

if(OPENMP_FOUND)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
  set(CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
  add_executable(test_writes test_writes.cpp)
else()
  message("Skipping test_writes, OpenMP required")
endif()
