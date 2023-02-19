# Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

cmake_minimum_required (VERSION 3.5.1)
project( Privateer LANGUAGES CXX C )

# create config file
include(CMakePackageConfigHelpers)
configure_package_config_file(
        "${PROJECT_SOURCE_DIR}/cmake/${PROJECT_NAME}Config.cmake.in"
        "${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
        INSTALL_DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/${PROJECT_NAME}/cmake)

set (CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)

set (CMAKE_C_STANDARD 17)

# cmake_policy(SET CMP0074 NEW)

set( default_build_type "Release" )
if ( EXISTS "${CMAKE_SOURCE_DIR}/.git" )
  set( default_build_type "Debug" )
endif()


FIND_PACKAGE(OpenSSL)

# option(USE_PAGEMAP_MSYNC ON)

# if (USE_PAGEMAP_MSYNC)
#  add_definitions(-DUSE_PAGEMAP)
# endif()


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

find_package(Boost) # COMPONENTS iostreams) # REQUIRED COMPONENTS system iostreams)

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


include_directories(include)
include_directories(src)

set(privateer_headers include/privateer/c_api/privateer.h include/privateer/privateer.hpp)
set(privateer_src src/privateer_c.cpp ${privateer_headers})

# add_library(privateer SHARED ${privateer_src} )
add_library(privateer-static STATIC ${privateer_src} )

# TARGET_LINK_LIBRARIES(privateer rt)
TARGET_LINK_LIBRARIES(privateer-static rt)
# TARGET_LINK_LIBRARIES(privateer OpenSSL::SSL)
TARGET_LINK_LIBRARIES(privateer-static OpenSSL::SSL)
# TARGET_LINK_LIBRARIES(privateer OpenSSL::Crypto)
TARGET_LINK_LIBRARIES(privateer-static OpenSSL::Crypto)

# File System
# TARGET_LINK_LIBRARIES(privateer stdc++fs)
TARGET_LINK_LIBRARIES(privateer-static stdc++fs)

# ZSTD
# ------------------ZSTD----------------------------
if (ZSTD_ROOT)
  find_library(LIBZSTD NAMES zstd PATHS ${ZSTD_ROOT}/lib)
  # target_include_directories(privateer PRIVATE ${ZSTD_ROOT}/lib)
  # target_link_libraries(privateer ${LIBZSTD})
  target_include_directories(privateer-static PRIVATE ${ZSTD_ROOT}/lib)
  target_link_libraries(privateer-static ${LIBZSTD})
  # target_compile_definitions(privateer PRIVATE USE_COMPRESSION)
  target_compile_definitions(privateer-static PRIVATE USE_COMPRESSION)
endif()
# --------------------------------------------------


# iostreams
# TARGET_LINK_LIBRARIES(privateer boost_iostreams)
# TARGET_LINK_LIBRARIES(privateer-static boost_iostreams)

set_target_properties(privateer-static PROPERTIES OUTPUT_NAME privateer)

install(TARGETS  privateer-static # Removed "privateer" from here
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin )

# install(FILES include/privateer/privateer.hpp DESTINATION include/privateer)
# install(FILES include/privateer/c_api/privateer.h DESTINATION include/privateer/c_api)

install(DIRECTORY include/privateer DESTINATION include)

# find_package(MPI)

# add_subdirectory(test_apps)
