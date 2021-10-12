# Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

project(incremental_update_snapshot)

FIND_PACKAGE( OpenMP REQUIRED )

if(OPENMP_FOUND)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
  set(CMAKE_EXE_LINKER_FLAGS
    "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
  add_executable(incremental_update_snapshot incremental_update_snapshot.cpp)
  add_executable(incremental_update_snapshot_open incremental_update_snapshot_open.cpp)
  add_executable(incremental_update_snapshot_skewed incremental_update_snapshot_skewed.cpp)
else()
  message("Skipping incremental_update_snapshot, OpenMP required")
endif()
