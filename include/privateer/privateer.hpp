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
  Privateer(int action, const char* base_path){
    if (action != CREATE && action != OPEN){
    std::cerr << "Privateer: Error - Invalid action" << std::endl;
    exit(-1);
    }
    if (action == CREATE){
      if (utility::directory_exists(base_path)){ // Do nothing, use existing
        /* std::cerr << "Privateer: Error creating datastore - base directory already exists, action must be PRIVATEER::OPEN" << std::endl;
        exit(-1); */
        std::cerr << "Using existing Privateer root dir at: " << base_path << std::endl;
        base_dir_path = std::string(base_path);
        blocks_dir_path = std::string(base_path) + "/" + "blocks";
        stash_dir_path = std::string(base_path) + "/" + "stash";
        // return;
      }
      else if (!utility::create_directory(base_path)){
        std::cerr << "Privateer: Error creating base directory at: " << base_path << " - " << strerror(errno) << std::endl;
        exit(-1);
      }
      init_block_size();
    }
    
    if (action == OPEN && !utility::directory_exists(base_path)){
      std::cerr << "Privateer: Error opening datastore - base directory does not exist, action must be PRIVATEER::CREATE" << std::endl;
      exit(-1);
    }
    base_dir_path = std::string(base_path);
    blocks_dir_path = std::string(base_path) + "/" + "blocks";
    stash_dir_path = std::string(base_path) + "/" + "stash";
  }
  
  Privateer(int action, const char* base_path, const char* stash_base_path){
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
        std::cerr << "Privateer: Error creating base directory at: " << base_path << " - " << strerror(errno) << std::endl;
        exit(-1);
      }
      /* if (!utility::create_directory(stash_base_path)){
        std::cerr << "Privateer: Error creating stash directory at: " << stash_base_path << " - " << strerror(errno) << std::endl;
        exit(-1);
      } */
    }
    if (!utility::directory_exists(stash_base_path)){
      if (!utility::create_directory(stash_base_path)){
        std::cerr << "Privateer: Error creating stash directory at: " << stash_base_path << " - " << strerror(errno) << std::endl;
        exit(-1);
      }
      /* std::cerr << "Privateer: Error creating datastore - stash directory already exists, action must be PRIVATEER::OPEN" << std::endl;
      exit(-1); */
    }
    
    if (action == OPEN && !utility::directory_exists(base_path)){
      std::cerr << "Privateer: Error opening datastore - base directory does not exist, action must be PRIVATEER::CREATE" << std::endl;
      exit(-1);
    }
    base_dir_path = std::string(base_path);
    blocks_dir_path = std::string(base_path) + "/" + "blocks";
    stash_dir_path = std::string(stash_base_path) + "/" + "stash";
  }

  ~Privateer(){
    struct sigaction sa;
    sa.sa_flags = SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    // sa.sa_sigaction = utility::sigsegv_handler_dispatcher::handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1){
      std::cerr << "Error: reset sigaction failed" << std::endl;
      exit(-1);
    }
    utility::sigsegv_handler_dispatcher::remove_virtual_memory_manager((uint64_t) vmm->get_region_start_address());
    delete vmm;
  }

  void* create(void* addr, const char* version_metadata_path, size_t region_size, bool allow_overwrite){
    std::string version_metadata_full_path = base_dir_path + "/" + version_metadata_path;
    vmm = new virtual_memory_manager(addr, region_size, m_block_size, version_metadata_full_path, blocks_dir_path, stash_dir_path, allow_overwrite);
    utility::sigsegv_handler_dispatcher::add_virtual_memory_manager((uint64_t) vmm->get_region_start_address(), region_size, vmm);
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

  void* open(void* addr, const char* version_metadata_path){
    return open(addr, version_metadata_path, false);
  }

  void* open_read_only(void* addr, const char* version_metadata_path){
    return open(addr, version_metadata_path, true);
  }
  
  void* open_immutable(void* addr, const char* version_metadata_path,  const char* new_version_metadata_path){
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

  void msync(){
    vmm->msync();
  }

  bool snapshot(const char* version_metadata_path){
    std::string version_metadata_full_path = base_dir_path + "/" + version_metadata_path;
    return vmm->snapshot(version_metadata_full_path.c_str());
  }

  size_t get_block_size(){
    return m_block_size;      
    // return vmm->get_block_size();
  }

  void* data(){
    return vmm->get_region_start_address();
  }

  bool version_exists(const char* version_metadata_path){
    std::string version_full_path = base_dir_path + "/" + version_metadata_path;
    return utility::directory_exists(version_full_path.c_str());
  }

  size_t region_size();
  static size_t version_capacity(std::string version_path);
  static size_t version_block_size(std::string version_path);
  static const int CREATE = 0;
  static const int OPEN = 1;

private:
  void* open(void* addr, const char *version_metadata_path, bool read_only){
    std::string version_metadata_full_path = base_dir_path + "/" + std::string(version_metadata_path);
    if(!utility::directory_exists(version_metadata_full_path.c_str())){
      std::cerr << "Error: Directory " << version_metadata_full_path << " does not exists" << std::endl;
      exit(-1);
    }
    version_metadata_dir_path = version_metadata_full_path;
    vmm = new virtual_memory_manager(addr, version_metadata_dir_path, stash_dir_path, read_only);
    utility::sigsegv_handler_dispatcher::add_virtual_memory_manager((uint64_t) vmm->get_region_start_address(), vmm->current_region_capacity(), vmm);
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

  void init_block_size(){
    if (m_block_size == 0){
    // Set block_size
      m_block_size = utility::get_environment_variable("PRIVATEER_BLOCK_SIZE");
      if (std::isnan((double)m_block_size) || m_block_size == 0){
        size_t num_blocks = utility::get_environment_variable("PRIVATEER_NUM_BLOCKS");
        if (std::isnan((double) num_blocks) || num_blocks == 0){
          m_block_size = FILE_GRANULARITY_DEFAULT_BYTES;
        }
        /* else{
          if (region_max_capacity % num_blocks == 0){
            m_block_size = region_max_capacity / num_blocks;
          }
          else{
            std::cerr << "PRIVATEER_NUM_BLOCKS is set, but region capacity is not divisible by it "<< std::endl;
            exit(-1);
          }
        } */
      }
      // Verify multiple of system's page size
      /* if (m_block_size % pagesize != 0){
        std::cerr << "Error: block_size must be multiple of system page size (" << pagesize << ")" << std::endl;
        exit(-1);
      } */
    }
  }

  std::string EMPTY_BLOCK_HASH;
  std::string base_dir_path;
  std::string blocks_dir_path;
  std::string stash_dir_path;
  std::string version_metadata_dir_path;
  size_t m_block_size = 0L;
  const size_t FILE_GRANULARITY_DEFAULT_BYTES = 2097152;
  size_t pagesize = sysconf(_SC_PAGE_SIZE);
  virtual_memory_manager* vmm;
};

inline size_t Privateer::region_size(){
  return vmm->current_region_capacity();
}

inline size_t Privateer::version_capacity(std::string version_path){
  return virtual_memory_manager::version_capacity(version_path);
}

inline size_t Privateer::version_block_size(std::string version_path){
  return virtual_memory_manager::version_block_size(version_path);
}
