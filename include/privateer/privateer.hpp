// Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
// See the top-level LICENSE file for details.
//
// SPDX-License-Identifier: MIT

#pragma once

#include <fcntl.h>
#include <spdlog/spdlog.h>
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

#include <privateer/utility/pagemap.hpp>
#include <privateer/utility/sha256_hash.hpp>
#include <privateer/utility/file_util.hpp>
#include <privateer/utility/system.hpp>
#include <privateer/virtual_memory_manager_base.hpp>
#include <privateer/virtual_memory_manager_factory.hpp>

#ifdef SIGACTION
#include <privateer/utility/sigsegv_handler_dispatcher.hpp>
#endif

#ifdef USERFAULTFD
#include <privateer/utility/UFFD.hpp>
#endif

namespace fs = std::filesystem;

class Privateer
{
public:
  /**
   * @brief Construct a new Privateer object
   * 
   * @param action
   * @param base_path 
   */
    Privateer(int action, const char* base_path){
#ifdef SIGACTION
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "Privateer: Constructor with SIGACTION");
#endif

#ifdef USERFAULTFD
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "Privateer: Constructor with USERFAULTFD");
#endif

    if (action != CREATE && action != OPEN){
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Invalid action");
      exit(-1);
    }
    if (action == CREATE){
      if (utility::directory_exists(base_path)){ // Do nothing, use existing
        /* SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Error creating datastore - base directory already exists, action must be PRIVATEER::OPEN");
        exit(-1); */
        //spdlog::warn("Privateer: Using existing Privateer root dir at {}", base_path);
        base_dir_path = std::string(base_path);
        blocks_dir_path = std::string(base_path) + "/" + "blocks";
        stash_dir_path = std::string(base_path) + "/" + "stash";
        // return; // TODO: uncommented in uffd variant?
      }
      else if (!utility::create_directory(base_path)){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Error creating base directory at {} - {}", base_path, strerror(errno));
        exit(-1);
      }
      init_block_size();
    }

    if (action == OPEN && !utility::directory_exists(base_path)){
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Error creating datastore - base directory does not exist, action must be PRIVATEER::CREATE");
      exit(-1);
    }
    base_dir_path = std::string(base_path);
    blocks_dir_path = std::string(base_path) + "/" + "blocks";
    stash_dir_path = std::string(base_path) + "/" + "stash";
  }

  /**
   * @brief Construct a new Privateer object with a specified stash path
   * 
   * @param action 
   * @param base_path 
   * @param stash_base_path 
   */
  Privateer(int action, const char* base_path, const char* stash_base_path){
 #ifdef SIGACTION
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "Privateer: Constructor (with stash path) with SIGACTION");
#endif

#ifdef USERFAULTFD
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "Privateer: Constructor (with stash path) with USERFAULTFD");
#endif
    if (action != CREATE && action != OPEN){
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Invalid action");
    exit(-1);
    }
    if (action == CREATE){
      if (utility::directory_exists(base_path)){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Error creating datastore - base directory already exists, action must be PRIVATEER::OPEN");
        exit(-1);
      }

      if (!utility::create_directory(base_path)){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Error creating base directory at {} - {}", base_path, strerror(errno));
        exit(-1);
      }
      /* if (!utility::create_directory(stash_base_path)){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Error creating stash directory at {} - {}", stash_base_path, strerror(errno));
        exit(-1);
      } */
    }
    if (!utility::directory_exists(stash_base_path)){
      if (!utility::create_directory(stash_base_path)){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Error creating stash directory at {} - {}", stash_base_path, strerror(errno));
        exit(-1);
      }
      /* SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Error creating datastore - stash directory already exists, action must be PRIVATEER::OPEN");
      exit(-1); */
    }

    if (action == OPEN && !utility::directory_exists(base_path)){
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Error opening datastore - base directory does not exist, action must be PRIVATEER::CREATE");
      exit(-1);
    }
    base_dir_path = std::string(base_path);
    blocks_dir_path = std::string(base_path) + "/" + "blocks";
    stash_dir_path = std::string(stash_base_path) + "/" + "stash";
  }

  /**
   * @brief Destroy the Privateer object
   * 
   */
  ~Privateer(){
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "Privateer: Destructor - starting");
    #ifdef SIGACTION
    struct sigaction sa;
    sa.sa_flags = SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    // sa.sa_sigaction = utility::sigsegv_handler_dispatcher::handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1){
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Reset sigaction failed");
      exit(-1);
    }
    utility::sigsegv_handler_dispatcher::remove_virtual_memory_manager((uint64_t) vmm->get_region_start_address());
    #endif

    #ifdef USERFAULTFD
    utility::UFFD::unregister_uffd_region((uint64_t)vmm->get_region_start_address(), vmm->current_region_capacity(), vmm);
    // SPDLOG_LOGGER_INFO(spdlog::default_logger(), "Before deleting VMM");
    utility::UFFD::stop_uffd();
    #endif

    delete vmm;
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "Privateer: Destructor - done");
  }

  /**
   * @brief Create a Privateer datastore
   * 
   * @param addr 
   * @param version_metadata_path 
   * @param region_size 
   * @param allow_overwrite 1
   * @return void* 1
   */
    void* create(void* addr, const char* version_metadata_path, size_t region_size, bool allow_overwrite){
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "Privateer: create()");
    std::string version_metadata_full_path = base_dir_path + "/" + version_metadata_path;
    vmm = virtual_memory_manager_factory::create(addr, region_size, m_block_size, version_metadata_full_path, blocks_dir_path, stash_dir_path, allow_overwrite);

    #ifdef SIGACTION
    utility::sigsegv_handler_dispatcher::add_virtual_memory_manager((uint64_t) vmm->get_region_start_address(), region_size, vmm);
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = utility::sigsegv_handler_dispatcher::handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1){
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: sigaction failed");
      exit(-1);
    }
    #endif

    #ifdef USERFAULTFD
    utility::UFFD::init_uffd();
    utility::UFFD::register_uffd_region((uint64_t)vmm->get_region_start_address(), vmm->current_region_capacity(), false, vmm);
    #endif

    return vmm->get_region_start_address();
  }
  /**
   * @brief Open an existing Privateer datastore
   * 
   * @param addr 
   * @param version_metadata_path 
   * @return void* 
   */
  void* open(void* addr, const char* version_metadata_path){
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "Privateer: open()");
    return open(addr, version_metadata_path, false);
  }

/**
 * @brief Open an existing Privateer datastore with read-only permission
 * 
 * @param addr 
 * @param version_metadata_path 
 * @return void* 
 */
  void* open_read_only(void* addr, const char* version_metadata_path){
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "Privateer: open_read_only()");
    return open(addr, version_metadata_path, true);
  }

/**
 * @brief Open an existing Privateer datastore without modifying
 * the original datastore. A copy is made similar to snapshot().
 * 
 * @param addr 
 * @param version_metadata_path 
 * @param new_version_metadata_path 
 * @return void* 
 */
  void* open_immutable(void* addr, const char* version_metadata_path,  const char* new_version_metadata_path){
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "Privateer: open_immutable()");
    std::string version_metadata_full_path = base_dir_path + "/" + std::string(version_metadata_path);
    std::string new_version_metadata_full_path = base_dir_path + "/" + std::string(new_version_metadata_path);
    // Check if datastore exist
    if(!utility::directory_exists(version_metadata_full_path.c_str())){
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Directory {} does not exist", version_metadata_full_path);
      throw "Directory Does Not Exists";
    }

    // Check if new directory exists
    if (utility::directory_exists(new_version_metadata_full_path.c_str())){
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: New version metadata directory already exists");
      exit(-1);
    }

    // Create new directory
    if (!utility::create_directory(new_version_metadata_full_path.c_str())){
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Error creating new version directory");
    }
    // Copy all metadata files
    std::string metadata_file = std::string(version_metadata_full_path) + "/_metadata";
    std::string size_file = std::string(version_metadata_full_path) + "/_capacity";
    std::string blocks_path_file = std::string(version_metadata_full_path) + "/_blocks_path";

    std::string new_metadata_file = std::string(new_version_metadata_full_path) + "/_metadata";
    std::string new_size_file = std::string(new_version_metadata_full_path) + "/_capacity";
    std::string new_blocks_path_file = std::string(new_version_metadata_full_path) + "/_blocks_path";

    if (!utility::copy_file(metadata_file.c_str(),new_metadata_file.c_str(), false)){
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Error copying metadata file");
      exit(-1);
    }
    if (!utility::copy_file(size_file.c_str(), new_size_file.c_str(), false)){
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Error copying capacity file");
      exit(-1);
    }
    if (!utility::copy_file(blocks_path_file.c_str(), new_blocks_path_file.c_str(), false)){
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Error copying blocks path file");
      exit(-1);
    }
    // Open new copy
    return open(addr, new_version_metadata_path, false);
  }

  /**
   * @brief Commit changes to datastore
   * 
   */
  void msync(){ // TODO: Inline?
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "Privateer: msync()");
    vmm->msync();
  }

  /**
   * @brief Commit changes and takes a snapshot of current changes made so far
   * 
   * @param version_metadata_path 
   * @return true 
   * @return false 
   */
  bool snapshot(const char* version_metadata_path){
    std::string version_metadata_full_path = base_dir_path + "/" + version_metadata_path;
    return vmm->snapshot(version_metadata_full_path.c_str());
  }

/**
 * @brief Get the block size object
 * 
 * @return size_t 
 */
  size_t get_block_size(){
    return m_block_size;
    // return vmm->get_block_size();
  }

/**
 * @brief Get the start address of a datastore region
 * 
 * @return void* 
 */
  void* data(){
    return vmm->get_region_start_address();
  }

/**
 * @brief Check version metadata
 * 
 * @param version_metadata_path 
 * @return true 
 * @return false 
 */
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
#ifdef SIGACTION
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "Opening with SIGACTION");
#endif

#ifdef USERFAULTFD
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "Opening with USERFAULTFD");
#endif

    std::string version_metadata_full_path = base_dir_path + "/" + std::string(version_metadata_path);
    if(!utility::directory_exists(version_metadata_full_path.c_str())){
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: Directory {} does not exist", version_metadata_full_path);
      exit(-1);
    }
    version_metadata_dir_path = version_metadata_full_path;
    vmm = virtual_memory_manager_factory::open(addr, version_metadata_dir_path, stash_dir_path, read_only);

    #ifdef SIGACTION
    utility::sigsegv_handler_dispatcher::add_virtual_memory_manager((uint64_t) vmm->get_region_start_address(), vmm->current_region_capacity(), vmm);
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = utility::sigsegv_handler_dispatcher::handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1){
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: sigaction failed");
      exit(-1);
    }
    #endif

    #ifdef USERFAULTFD
    utility::UFFD::init_uffd();
    utility::UFFD::register_uffd_region((uint64_t)vmm->get_region_start_address(), vmm->current_region_capacity(), false, vmm);
    #endif

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
          SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: PRIVATEER_NUM_BLOCKS is set, but region capacity is not divisible by it");
            exit(-1);
          }
        } */
      }
      // Verify multiple of system's page size
      /* if (m_block_size % pagesize != 0){
         SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Privateer: block_size must be multiple of system page size ({})", pagesize);
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
  virtual_memory_manager_base* vmm;
};

/**
 * @brief Get region size
 *
 * @return region size
 */
inline size_t Privateer::region_size(){
  return vmm->current_region_capacity();
}

/**
 * @brief Get version capacity
 *
 * @param version_path
 * @return version capacity
 */
inline size_t Privateer::version_capacity(std::string version_path){
  return virtual_memory_manager_base::version_capacity(version_path);
}

/**
 * @brief Get version block size
 *
 * @param version_path
 * @return version block size
 */
inline size_t Privateer::version_block_size(std::string version_path){
  return virtual_memory_manager_base::version_block_size(version_path);
}
