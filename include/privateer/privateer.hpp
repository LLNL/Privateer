// Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
// See the top-level LICENSE file for details.
//
// SPDX-License-Identifier: MIT

#pragma once

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <cassert>
#include <sys/stat.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <filesystem>
#include <cerrno>
#include <cstring>
#include <clocale>
#include <bits/stdc++.h>
#include <string>
#include <stdio.h>
#include <cmath>
#include <omp.h>
#include <sstream>
#include <signal.h>

#include "utility/pagemap.hpp"
#include "utility/sha256_hash.hpp"
#include "utility/file_util.hpp"
#include "utility/system.hpp"
#include "utility/sigsegv_handler_dispatcher.hpp"
#include "virtual_memory_manager.hpp"

namespace fs = std::filesystem;

class Privateer
{
public:
  Privateer(int action, const char* base_path);

  ~Privateer();

  void* create(void* addr, const char* version_metadata_path, size_t size);
  void* open(void* addr, const char* version_metadata_path);
  void* open_read_only(void* addr, const char* version_metadata_path);
  void* open_immutable(void* addr, const char* version_metadata_path,  const char* new_version_metadata_path);
  void msync();
  bool snapshot(const char* version_metadata_path);
  void* data();
  size_t region_size();
  static size_t version_size(std::string version_path);
  static size_t version_capacity(std::string version_path);
  static const int CREATE;
  static const int OPEN;

private:
  void* open(void* address, const char* version_metadata_path, bool read_only);
  void *m_addr;
  uint64_t m_max_size;
  std::string* blocks;
  void **regions;
  static size_t const FILE_GRANULARITY_DEFAULT_BYTES;
  static size_t const MAX_MEM_DEFAULT_BLOCKS;
  static size_t const HASH_SIZE;
  std::string EMPTY_BLOCK_HASH;
  std::string base_dir_path;
  std::string blocks_dir_path;
  std::string stash_dir_path;
  std::string version_metadata_dir_path;
  int metadata_fd;
  size_t file_granularity;
  size_t max_mem_size_blocks;
  std::map<std::string,int> block_file_exist_map;
  bool m_read_only;
  virtual_memory_manager* vmm;
};

size_t const Privateer::FILE_GRANULARITY_DEFAULT_BYTES = 2*134217728; // 128 MBs 
size_t const Privateer::MAX_MEM_DEFAULT_BLOCKS = 1024;
size_t const Privateer::HASH_SIZE = 64; // size of SHA-256 hash
int const Privateer::CREATE = 0;
int const Privateer::OPEN = 1;

Privateer::Privateer(int action, const char* base_path){
  if (action != CREATE && action != OPEN){
    std::cerr << "Privateer: Error - Invalid action" << std::endl;
    exit(-1);
  }
  if (action == CREATE){
    if (utility::directory_exists(base_path)){
      std::cerr << "Privateer: Error creating datastore - base directory already exists, action must be PRIVATEER::OPEN" << std::endl;
      exit(-1);
    }
    if (!utility::create_directory(base_path)){
      std::cerr << "Privateer: Error creating base directory at: " << base_path << "- " << strerror(errno) << std::endl;
      exit(-1);
    }
    
  }
  
  if (action == OPEN && !utility::directory_exists(base_path)){
    std::cerr << "Privateer: Error opening datastore - base directory does not exist, action must be PRIVATEER::CREATE" << std::endl;
    exit(-1);
  }
  base_dir_path = std::string(base_path);
  blocks_dir_path = std::string(base_path) + "/" + "blocks";
  stash_dir_path = std::string(base_path) + "/" + "stash";
}

void* Privateer::create(void *addr,const char *version_metadata_path, size_t max_capacity){
  // Verify system page alignment
  size_t pagesize = sysconf(_SC_PAGE_SIZE);
  /* if (original_size % pagesize != 0){
    std::cerr << "Error: Size must be multiple of page size (" << pagesize << ")" << std::endl;
  } */
  if (max_capacity % pagesize != 0){
    std::cerr << "Error: Capacity must be multiple of system page size (" << pagesize << ")" << std::endl;
    exit(-1);
  }
  // create version metadata directory
  version_metadata_dir_path = base_dir_path + "/" + std::string(version_metadata_path);
  if (blocks_dir_path.compare(version_metadata_dir_path) != 0){
    if (utility::directory_exists(version_metadata_dir_path.c_str())){
      std::cerr << "Error: Version metadata directory already exists" << std::endl;
      exit(-1);
    }
    if (!utility::create_directory(version_metadata_dir_path.c_str())){
      std::cerr << "Error: Failed to create version metadata directory" << std::endl;
    }
  }
  // Create blocks metadata file
  std::string metadata_file_name = std::string(version_metadata_dir_path) + "/_metadata";
  metadata_fd = ::open(metadata_file_name.c_str(), O_RDWR | O_CREAT | O_EXCL, (mode_t) 0666);
  if (metadata_fd == -1){
    std::cerr << "Privateer: Error opening metadata file: " << metadata_file_name << " - " << strerror(errno) << std::endl;
    exit(-1);
  }

  // Create file to save blocks path
  std::string blocks_path_file_name = std::string(version_metadata_dir_path) + "/_blocks_path";
  std::ofstream blocks_path_file;
  blocks_path_file.open(blocks_path_file_name);
  blocks_path_file << blocks_dir_path;
  blocks_path_file.close();

  // Set file granularity
  file_granularity = utility::get_environment_variable("PRIVATEER_FILE_GRANULARITY");
  if ( std::isnan(file_granularity) || file_granularity == 0){
    file_granularity = FILE_GRANULARITY_DEFAULT_BYTES;
  }
  max_mem_size_blocks = utility::get_environment_variable("PRIVATEER_MAX_MEM_BLOCKS");
  if ( std::isnan(max_mem_size_blocks) || max_mem_size_blocks == 0){
    max_mem_size_blocks = MAX_MEM_DEFAULT_BLOCKS;
  } 
  std::cout << "block size: " << file_granularity << std::endl;
  // Handling if requested size is less than file granularity
  file_granularity = std::min(max_capacity, file_granularity);

  // init block hashes array
  size_t num_blocks = (size_t)ceil(max_capacity*1.0 / file_granularity);

  size_t ceiled_max_capacity = num_blocks*file_granularity;
  m_max_size = ceiled_max_capacity;

  // Create capacity file
  std::string capacity_file_name = std::string(version_metadata_dir_path) + "/_capacity";
  std::ofstream capacity_file;
  capacity_file.open(capacity_file_name);
  capacity_file << m_max_size;
  capacity_file.close();

  vmm = new virtual_memory_manager(addr, file_granularity, m_max_size, max_mem_size_blocks,
                                    version_metadata_dir_path, blocks_dir_path, stash_dir_path);
  utility::sigsegv_handler_dispatcher::set_virtual_memory_manager(vmm);
  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = utility::sigsegv_handler_dispatcher::handler;
  if (sigaction(SIGSEGV, &sa, NULL) == -1){
    std::cerr << "Error: sigaction failed" << std::endl;
    exit(-1);
  }
  return vmm->get_region_start_address();
}

void* Privateer::open(void* addr, const char *version_metadata_path){
  return open(addr, version_metadata_path, false);
}

void* Privateer::open_read_only(void* addr, const char *version_metadata_path){
  return open(addr, version_metadata_path, true);
}

// TODO: Change this and support it in VMM
void* Privateer::open_immutable(void *addr, const char *version_metadata_path, const char *new_version_metadata_path){
  std::string version_metadata_full_path = base_dir_path + "/" + std::string(version_metadata_path);
  std::string new_version_metadata_full_path = base_dir_path + "/" + std::string(new_version_metadata_path);
  // Check if datastore exist
  if(!utility::directory_exists(version_metadata_full_path.c_str())){
    std::cerr << "Error: Directory " << version_metadata_full_path << " does not exists" << std::endl;
    throw "Directory Does Not Exists";
  }

  // Check if new directory exists
  if (utility::directory_exists(new_version_metadata_full_path.c_str())){
    std::cerr << "Error: New version metadata directory already exists" << std::endl;
    exit(-1);
  }

  // Create new directory
  if (!utility::create_directory(new_version_metadata_full_path.c_str())){
    std::cerr << "Privateer: Error creating new version directory" << std::endl;
  }
  // Copy all metadata files
  std::string metadata_file = std::string(version_metadata_full_path) + "/_metadata";
  std::string size_file = std::string(version_metadata_full_path) + "/_capacity";
  std::string blocks_path_file = std::string(version_metadata_full_path) + "/_blocks_path";

  std::string new_metadata_file = std::string(new_version_metadata_full_path) + "/_metadata";
  std::string new_size_file = std::string(new_version_metadata_full_path) + "/_capacity";
  std::string new_blocks_path_file = std::string(new_version_metadata_full_path) + "/_blocks_path";

  if (!utility::copy_file(metadata_file.c_str(),new_metadata_file.c_str(), false)){
    std::cerr << "Privateer: Error Copying metada file" << std::endl;
    exit(-1);
  }
  if (!utility::copy_file(size_file.c_str(), new_size_file.c_str(), false)){
    std::cerr << "Privateer: Error Copying capacity file" << std::endl;
    exit(-1);
  }
  if (!utility::copy_file(blocks_path_file.c_str(), new_blocks_path_file.c_str(), false)){
    std::cerr << "Privateer: Error Copying blocks path file" << std::endl;
    exit(-1);
  }
  // Open new copy
  return open(addr, new_version_metadata_path, false);
}

void* Privateer::open(void* addr, const char *version_metadata_path, bool read_only){

  std::string version_metadata_full_path = base_dir_path + "/" + std::string(version_metadata_path);
  // Check if datastore exist
  if(!utility::directory_exists(version_metadata_full_path.c_str())){
    std::cerr << "Error: Directory " << version_metadata_full_path << " does not exists" << std::endl;
    exit(-1);
  }

  version_metadata_dir_path = version_metadata_full_path;

  max_mem_size_blocks = utility::get_environment_variable("PRIVATEER_MAX_MEM_BLOCKS");
  if ( std::isnan(max_mem_size_blocks) || max_mem_size_blocks == 0){
    max_mem_size_blocks = MAX_MEM_DEFAULT_BLOCKS;
  } 
  
  vmm = new virtual_memory_manager(addr, version_metadata_dir_path, stash_dir_path, read_only, max_mem_size_blocks);

  utility::sigsegv_handler_dispatcher::set_virtual_memory_manager(vmm);
  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = utility::sigsegv_handler_dispatcher::handler;
  if (sigaction(SIGSEGV, &sa, NULL) == -1){
    std::cerr << "Error: sigaction failed" << std::endl;
    exit(-1);
  }
  return vmm->get_region_start_address();
}

inline void Privateer::msync(){
  vmm->msync();
}


bool Privateer::snapshot(const char* version_metadata_path){
  std::string version_metadata_full_path = base_dir_path + "/" + version_metadata_path;
  return vmm->snapshot(version_metadata_full_path.c_str());
}



// TODO: Redo after finalizing virtual_memomry_manager
inline Privateer::~Privateer()
{
  /* void* status = mmap(m_addr, m_current_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (status == MAP_FAILED){
    std::cerr << "Privateer: Error releasing region" << std::endl;
    exit(-1);
  } 
  std::cout << "Done unmapping regions" << std::endl; */
  
  
  /* delete [] regions;
  std::cout << "Done deleting regions" << std::endl;
  
  delete [] blocks;
  std::cout << "Done deleting blocks" << std::endl; */
  
  delete vmm;
  /* std::cout << "Done deleting block storage" << std::endl;
  int close_metadata = ::close(metadata_fd);
  std::cout << "Privateer: Object destroyed successfully" << std::endl; */
}

// TODO: Update to be vmm->region_ptr
inline void* Privateer::data(){
  return vmm->get_region_start_address();
}

// TODO: Update to be vmm->region_size
inline size_t Privateer::region_size(){
  return m_max_size;
}

inline size_t Privateer::version_capacity(std::string version_path){
  // Read size path
  std::string size_string;
  std::string size_file_name = std::string(version_path) + "/_capacity";
  std::ifstream size_file;
  size_file.open(size_file_name);
  if (!size_file.is_open()){
    std::cerr << "Error opening size file path at: " << size_file_name << std::endl;
    return (size_t) -1;
  }
  if (!std::getline(size_file, size_string)){
    std::cerr << "Error reading reading file" << std::endl;
    return (size_t) -1;
  }
  try {
    size_t size = std::stol(size_string);
    return size;
  }
  catch (const std::invalid_argument& ia){
    std::cerr << "Error parsing version size from file - " << ia.what() << std::endl;
    return (size_t) -1;
  }
}
