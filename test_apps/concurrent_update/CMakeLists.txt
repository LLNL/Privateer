# Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

project(concurrent_update)

include_directories(SYSTEM ${MPI_INCLUDE_PATH})

if (MPI_CXX_FOUND)
    add_executable(concurrent_update concurrent_update.cpp)
    target_link_libraries(concurrent_update PUBLIC MPI::MPI_CXX) # ::MPI_CXX)
    if (${CMAKE_HOST_SYSTEM_NAME} MATCHES "Linux")
        target_link_libraries(concurrent_update PUBLIC rt)
    endif()
else()
    message(STATUS "Will skip building the MPI examples")
endif()
