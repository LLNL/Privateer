# Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

cmake_minimum_required (VERSION 3.5.1)
project( Privateer LANGUAGES CXX C )

if(POLICY CMP0074)
  cmake_policy(SET CMP0074 NEW)
endif()

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

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

set( default_build_type "Release" )
if ( EXISTS "${CMAKE_SOURCE_DIR}/.git" )
  set( default_build_type "Debug" )
endif()




# OpenSSL
# link_libraries(OpenSSL::SSL)
# link_libraries(OpenSSL::Crypto)

# File System
# link_libraries(stdc++fs)

include(CheckCXXSourceCompiles)

# ------------------OpenMP--------------------------
FIND_PACKAGE( OpenMP REQUIRED )

if(OPENMP_FOUND)
  set(PRIVATEER_OPENMP_TARGET OpenMP::OpenMP_CXX)
else()
  message(FATAL_ERROR "Error: OpenMP not found")
endif()
# --------------------------------------------------

include(FetchContent)
# ------------------ Boost -------------------------------------------------------------------------------
set(Boost_NO_SYSTEM_PATHS OFF)
set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)

find_package(Boost CONFIG QUIET)
if(NOT Boost_FOUND)
  set(CMAKE_FIND_PACKAGE_PREFER_CONFIG FALSE)
  if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
  endif()
  find_package(Boost QUIET)
endif()

if (Boost_FOUND)

  # Just a sanity check
  if (NOT Boost_INCLUDE_DIRS)
    message(FATAL_ERROR "Something is wrong: Boost_INCLUDE_DIRS is empty although Boost_FOUND is true.")
  endif()
  include_directories(${Boost_INCLUDE_DIRS})
else ()
  message(STATUS "Download and setup Boost")
  FetchContent_Declare(Boost
    URL https://archives.boost.io/release/1.82.0/source/boost_1_82_0.tar.bz2
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_GetProperties(Boost)
  if (NOT Boost_POPULATED)
    FetchContent_Populate(Boost)
  endif ()
  set(BOOST_ROOT ${boost_SOURCE_DIR})
  set(CMAKE_FIND_PACKAGE_PREFER_CONFIG FALSE)
  if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
  endif()
  find_package(Boost 1.82 REQUIRED)
  include_directories(${Boost_INCLUDE_DIRS})
endif ()

# ---------------------------------------------------------------------------------------------------------- 


include_directories(include)
include_directories(src)

# Base classes and interfaces
set(privateer_base_headers
    include/privateer/c_api/privateer.h
    include/privateer/privateer.hpp
    include/privateer/virtual_memory_manager_base.hpp
    include/privateer/block_storage_base.hpp)

set(privateer_base_src
    src/privateer/virtual_memory_manager_base.cpp
    src/privateer/block_storage_base.cpp)

# Derived implementations
set(privateer_impl_headers
    include/privateer/sigaction_virtual_memory_manager.hpp
    include/privateer/uffd_virtual_memory_manager.hpp
    include/privateer/posix_block_storage.hpp
    include/privateer/smartcache_block_storage.hpp)

set(privateer_impl_src
    src/privateer/sigaction_virtual_memory_manager.cpp
    src/privateer/uffd_virtual_memory_manager.cpp
    src/privateer/posix_block_storage.cpp
    src/privateer/smartcache_block_storage.cpp)

# Factories
set(privateer_factory_headers
    include/privateer/virtual_memory_manager_factory.hpp
    include/privateer/block_storage_factory.hpp)

set(privateer_factory_src
    src/privateer/virtual_memory_manager_factory.cpp
    src/privateer/block_storage_factory.cpp)

# C API
set(privateer_c_src src/privateer_c.cpp)

# Combine all sources
set(privateer_headers ${privateer_base_headers} ${privateer_impl_headers} ${privateer_factory_headers})
set(privateer_src ${privateer_base_src} ${privateer_impl_src} ${privateer_factory_src} ${privateer_c_src} ${privateer_headers})

add_library(privateer STATIC ${privateer_src})
# add_library(privateer-static STATIC ${privateer_src} )

target_link_libraries(privateer PUBLIC ${PRIVATEER_OPENMP_TARGET})

find_package(OpenSSL REQUIRED)
target_link_libraries(privateer PUBLIC rt)
# target_link_libraries(privateer-static PUBLIC rt)
target_link_libraries(privateer PUBLIC OpenSSL::SSL)
# target_link_libraries(privateer-static PUBLIC OpenSSL::SSL)
target_link_libraries(privateer PUBLIC OpenSSL::Crypto)
# target_link_libraries(privateer-static PUBLIC OpenSSL::Crypto)

# File System
set(CMAKE_REQUIRED_FLAGS "-std=c++17")
check_cxx_source_compiles("#include <filesystem>
int main() { std::filesystem::path p{\".\"}; return 0; }" PRIVATEER_HAS_NATIVE_FILESYSTEM)
unset(CMAKE_REQUIRED_FLAGS)

if(NOT PRIVATEER_HAS_NATIVE_FILESYSTEM)
  target_link_libraries(privateer PUBLIC stdc++fs)
endif()
# target_link_libraries(privateer-static PUBLIC stdc++fs)

# ZSTD
# ------------------ZSTD----------------------------
option(ENABLE_ZSTD "Enable compression" OFF)
if (ENABLE_ZSTD)
  message(STATUS "Configuring with zstd")
  list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
  find_package(zstd REQUIRED)
  # target_include_directories(privateer-static PUBLIC ${ZSTD_INCLUDE_DIRS})
  # target_link_libraries(privateer-static PUBLIC zstd::zstd)
  # target_compile_definitions(privateer-static PUBLIC USE_COMPRESSION)
  target_include_directories(privateer PUBLIC ${ZSTD_INCLUDE_DIRS})
  target_link_libraries(privateer PUBLIC zstd::zstd)
  target_compile_definitions(privateer PUBLIC USE_COMPRESSION)
endif()
# --------------------------------------------------

# SPDLOG
# ------------------SPDLOG----------------------------
#option(ENABLE_SPDLOG "Enable logging" OFF)
#if (ENABLE_SPDLOG)
# set(SPDLOG_BUILD_SHARED ON CACHE BOOL "" FORCE)
message(STATUS "Configuring with spdlog")
FetchContent_Declare(spdlog
  URL https://github.com/gabime/spdlog/archive/refs/tags/v1.14.1.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(spdlog)
include_directories(${spdlog_INCLUDE_DIRS})
# target_link_libraries(privateer-static PUBLIC spdlog::spdlog)
target_link_libraries(privateer PUBLIC spdlog::spdlog)
target_compile_definitions(privateer PUBLIC SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_INFO)
# --------------------------------------------------

# iostreams
# TARGET_LINK_LIBRARIES(privateer boost_iostreams)
# TARGET_LINK_LIBRARIES(privateer-static boost_iostreams)

# set_target_properties(privateer-static PROPERTIES OUTPUT_NAME privateer)

install(TARGETS  privateer # Removed "privateer-static" from here
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin )

# install(FILES include/privateer/privateer.hpp DESTINATION include/privateer)
# install(FILES include/privateer/c_api/privateer.h DESTINATION include/privateer/c_api)

install(DIRECTORY include/privateer DESTINATION include)

option(ENABLE_UFFD "Enable userfaultfd" OFF)
if (ENABLE_UFFD)
  # target_compile_definitions(privateer-static PUBLIC USERFAULTFD)
  target_compile_definitions(privateer PUBLIC USERFAULTFD)
  message(STATUS "Configuring with UFFD")
else()
  # target_compile_definitions(privateer-static PUBLIC SIGACTION)
  target_compile_definitions(privateer PUBLIC SIGACTION)
  message(STATUS "Configuring with SIGACTION")
endif()

option(ENABLE_PAGE_EVICTION "Enable page eviction" OFF)
if (ENABLE_PAGE_EVICTION)
  target_compile_definitions(privateer PUBLIC ENABLE_PAGE_EVICTION)
  # target_compile_definitions(privateer PUBLIC USERFAULTFD)
  message(STATUS "Configuring with Page Eviction")
else()
  message(STATUS "Configuring without Page Eviction")
endif()

find_package(MPI)

option(ENABLE_PRIVATEER_TEST  "Enable Testing" ON)
if (ENABLE_PRIVATEER_TEST)
  include(CTest)
  enable_testing()
  add_subdirectory(test)
endif()

option(ENABLE_PRIVATEER_EXAMPLES "Enable examples" ON)
if (ENABLE_PRIVATEER_EXAMPLES)
  add_subdirectory(examples)
endif()
