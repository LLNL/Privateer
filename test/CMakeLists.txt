# Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

include(GoogleTest)

function(add_gtest_executable test_name test_file)
    add_executable(${test_name} ${test_file})
    target_link_libraries(${test_name} PRIVATE GTest::gtest GTest::gtest_main)
    # add_dependencies(${test_name} privateer-static)
    # target_link_libraries(${test_name} PUBLIC privateer-static)
    add_dependencies(${test_name} privateer)
    target_link_libraries(${test_name} PUBLIC privateer)
    gtest_discover_tests(${test_name})
endfunction()

add_gtest_executable(PrivateerTest PrivateerTest.cpp)



if (MPI_CXX_FOUND)
  target_link_libraries(PrivateerTest PRIVATE MPI::MPI_CXX)
else()
  message(STATUS "Will skip the MPI tests")
endif()
