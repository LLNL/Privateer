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

#include "utility/pagemap.hpp"
#include "utility/sha256_hash.hpp"
#include "utility/file_util.hpp"
#include "utility/system.hpp"
#include "block_storage.hpp"

namespace fs = std::filesystem;

class Privateer
{
public:
  // Create
  Privateer(void *addr, const char *blocks_dir_path, const char *version_metadata_path, size_t max_capacity);
  Privateer(const char *blocks_dir_path, const char *version_metadata_path, size_t max_capacity);

  // Create with original size
  Privateer(void *addr, const char *blocks_dir_path, const char *version_metadata_path, size_t original_size, size_t max_capacity);
  Privateer(const char *blocks_dir_path, const char *version_metadata_path, size_t original_size, size_t max_capacity);

  // Open while preserving of snapshot (write to new snapshot)
  Privateer(void *addr, const char *version_metadata_path, const char *new_version_metadata_path);
  Privateer(const char *version_metadata_path, const char *new_version_metadata_path);

  // Open and enable updating snapshot
  Privateer(void *addr, const char *version_metadata_path, bool read_only);
  Privateer(const char *version_metadata_path, bool read_only);

  ~Privateer();

  bool resize(size_t size);
  void msync();
  bool snapshot(const char* version_metadata_path);
  void* data();
  size_t current_size();
  size_t max_size();
  static size_t version_size(std::string version_path);
  static size_t version_capacity(std::string version_path);

private:
  void create(void *addr, const char *blocks_dir_path, const char *version_metadata_path, size_t max_capacity);

  void create(void *addr, const char *blocks_dir_path, const char *version_metadata_path, size_t original_size, size_t max_capacity);

  void open(void *addr, const char *version_metadata_path, const char *new_version_metadata_path);

  void open(void* addr, const char *version_metadata_path, bool read_only);

  void msync_memcopy();

  void msync_pagemap();

  void msync_pagemap_block_no_copy(void* block_start, size_t block_size);

  void validate(int region_index, int fd);

  void update_metadata();

  void *m_addr;
  uint64_t m_max_size;
  uint64_t m_current_size;
  int* m_fds; // Array of fds
  std::string* blocks;
  void **regions;
  static size_t const FILE_GRANULARITY_DEFAULT_BYTES;
  static size_t const HASH_SIZE;
  std::string EMPTY_BLOCK_HASH;
  std::string blocks_dir_path;
  std::string version_metadata_dir_path;
  int metadata_fd;
  size_t file_granularity;
  std::map<std::string,int> block_file_exist_map;
  bool m_read_only;
  BlockStorage* block_storage;
};

size_t const Privateer::FILE_GRANULARITY_DEFAULT_BYTES = 2*134217728; // 128 MBs 
size_t const Privateer::HASH_SIZE = 64; // size of SHA-256 hash

// Create interface
inline Privateer::Privateer(void *addr, const char *blocks_path, const char *version_metadata_path, size_t max_capacity)
{
  create(addr, blocks_path, version_metadata_path, max_capacity);
}

inline Privateer::Privateer(const char *blocks_path, const char *version_metadata_path, size_t max_capacity)
{
  create(nullptr, blocks_path, version_metadata_path, max_capacity);
}

inline Privateer::Privateer(void *addr, const char *blocks_path, const char *version_metadata_path, size_t original_size, size_t max_capacity)
{
  create(addr, blocks_path, version_metadata_path, original_size, max_capacity);
}

inline Privateer::Privateer(const char *blocks_path, const char *version_metadata_path, size_t original_size, size_t max_capacity)
{
  create(nullptr, blocks_path, version_metadata_path, original_size, max_capacity);
}

// Open interface
inline Privateer::Privateer(const char *version_metadata_path, const char *new_version_metadata_path)
{
  open(nullptr, version_metadata_path, new_version_metadata_path);
}

inline Privateer::Privateer(void *addr, const char *version_metadata_path, const char *new_version_metadata_path)
{
  open(addr, version_metadata_path, new_version_metadata_path);
}

inline Privateer::Privateer(const char *version_metadata_path, bool read_only)
{
  open(nullptr, version_metadata_path, read_only);
}

inline Privateer::Privateer(void* addr, const char *version_metadata_path, bool read_only)
{
  open(addr, version_metadata_path, read_only);
}

inline void Privateer::create(void *addr, const char *blocks_path, const char *version_metadata_path, size_t max_capacity)
{
  // Verify page alignment
  size_t pagesize = sysconf(_SC_PAGE_SIZE);
  if (max_capacity % pagesize != 0){
    std::cerr << "Error: Capacity must be multiple of page size (" << pagesize << " Bytes) " << std::endl;
    exit(-1);
  }
  // Set file granularity
  file_granularity = utility::get_environment_variable("PRIVATEER_FILE_GRANULARITY");
  if ( std::isnan(file_granularity) || file_granularity == 0){
    // std::cout << "Privateer: Using default file granularity of : " << FILE_GRANULARITY_DEFAULT_BYTES << " bytes." << std::endl;
    file_granularity = FILE_GRANULARITY_DEFAULT_BYTES;
  }
  // Handling if requested size is less than file granularity
  file_granularity = std::min(max_capacity, file_granularity);
  // Call the other create()
  create(addr, blocks_path, version_metadata_path, file_granularity, max_capacity);
}

inline void Privateer::create(void *addr, const char *blocks_path, const char *version_metadata_path, size_t original_size, size_t max_capacity)
{
  // Verify page alignment
  size_t pagesize = sysconf(_SC_PAGE_SIZE);
  if (original_size % pagesize != 0){
    std::cerr << "Error: Size must be multiple of page size (" << pagesize << ")" << std::endl;
  }
  if (max_capacity % pagesize != 0){
    std::cerr << "Error: Capacity must be multiple of page size (" << pagesize << ")" << std::endl;
  }

  // std::cout << "Privateer: creating region with Capacity: " << max_capacity << " at address " << (uint64_t) addr << std::endl;

  // create version metadata directory
  version_metadata_dir_path = version_metadata_path;
  if (blocks_dir_path.compare(version_metadata_dir_path) != 0){
    if (utility::directory_exists(version_metadata_dir_path.c_str())){
      std::cerr << "Error: Version metadata directory already exists" << std::endl;
      exit(-1);
    }
    if (!utility::create_directory(version_metadata_dir_path.c_str())){
      std::cerr << "Error: Failed to create version metadata directory" << std::endl;
    }
  }
  blocks_dir_path = blocks_path;
  version_metadata_dir_path = version_metadata_path;

  // Create blocks metadata file
  std::string metadata_file_name = std::string(version_metadata_path) + "/_metadata";
  metadata_fd = ::open(metadata_file_name.c_str(), O_RDWR | O_CREAT | O_EXCL, (mode_t) 0666);
  assert(metadata_fd != -1);

  // Create file to save blocks path
  std::string blocks_path_file_name = std::string(version_metadata_path) + "/_blocks_path";
  std::ofstream blocks_path_file;
  blocks_path_file.open(blocks_path_file_name);
  blocks_path_file << blocks_dir_path;
  blocks_path_file.close();

  // Set file granularity
  file_granularity = utility::get_environment_variable("PRIVATEER_FILE_GRANULARITY");
  if ( std::isnan(file_granularity) || file_granularity == 0){
    file_granularity = FILE_GRANULARITY_DEFAULT_BYTES;
  }


  // Handling if requested size is less than file granularity
  file_granularity = std::min(max_capacity, file_granularity);

  // Create size file
  m_current_size = original_size;
  std::string size_file_name = std::string(version_metadata_path) + "/_size";
  std::ofstream size_file;
  size_file.open(size_file_name);
  size_file << m_current_size;
  size_file.close();



  // create blocks base directory
  block_storage = new BlockStorage(blocks_path, file_granularity);

  // init block hashes array
  size_t num_blocks = (size_t)ceil(max_capacity*1.0 / file_granularity);

  size_t ceiled_max_capacity = num_blocks*file_granularity;
  m_max_size = ceiled_max_capacity;

  // Create capacity file
  std::string capacity_file_name = std::string(version_metadata_path) + "/_capacity";
  std::ofstream capacity_file;
  capacity_file.open(capacity_file_name);
  capacity_file << m_max_size;
  capacity_file.close(); 

  // mmap region with full size
  int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE;
  if (addr != nullptr)
  {
    flags |= MAP_FIXED;
  }

  m_addr = mmap(addr, ceiled_max_capacity, PROT_NONE, flags, -1, 0);
  if (m_addr == MAP_FAILED){
    std::cerr << "Privateer276: mmap error - " << strerror(errno)<< std::endl;
    exit(-1);
  }
  //init regions
  regions = new void*[num_blocks];
  for (size_t i = 0; i < num_blocks; i++){
    regions[i] = (size_t) 0;
  }

  size_t num_init_regions = original_size / file_granularity;
  for (size_t i = 0; i < num_init_regions; i++){
    uint64_t offset = (uint64_t) m_addr + i*file_granularity;
    regions[i] = mmap((void*) offset, file_granularity, PROT_READ | PROT_WRITE, flags | MAP_FIXED, -1, 0);
    if (regions[0] == MAP_FAILED){
      std::cerr << "Privateer291: mmap error - " << strerror(errno)<< std::endl;
      exit(-1);
    }
  }

  // Initializing block hashes (file recipe)
  blocks = new std::string[num_blocks];
  std::string empty_block_hash(HASH_SIZE,'0');
  EMPTY_BLOCK_HASH = empty_block_hash;

  for (size_t i = 0 ; i < num_blocks ; i++){
    blocks[i] = EMPTY_BLOCK_HASH;
  }

  m_read_only = false;
}

inline void Privateer::open(void* addr, const char *version_metadata_path, bool read_only){

  // Check if datastore exist
  if(!utility::directory_exists(version_metadata_path)){
    std::cerr << "Error: Directory " << version_metadata_path << " does not exists" << std::endl;
    throw "Directory Does Not Exists";
  }

  version_metadata_dir_path = version_metadata_path;
  // Read blocks path
  std::string blocks_path_file_name = std::string(version_metadata_path) + "/_blocks_path";
  std::ifstream blocks_path_file;
  blocks_path_file.open(blocks_path_file_name);
  if (!blocks_path_file.is_open()){
    std::cerr << "Error opening blocks file path at: " << blocks_path_file_name << std::endl;
  }
  if (!std::getline(blocks_path_file, blocks_dir_path)){
    std::cerr << "Error reading blocks path file" << std::endl;
  }

  // Open block storage
  block_storage = new BlockStorage(blocks_dir_path);
  file_granularity = block_storage->get_block_granularity();

  // Get current size
  m_current_size = version_size(version_metadata_path);
  size_t num_blocks_current_size = m_current_size / file_granularity;

  // Open existing metadata file and get size
  m_read_only = read_only;
  std::string metadata_file_name = std::string(version_metadata_path) + "/_metadata";
  int flags = read_only? O_RDONLY: O_RDWR;
  metadata_fd = ::open(metadata_file_name.c_str(), flags, (mode_t) 0666);
  assert(metadata_fd != -1);
  struct stat st;
  fstat(metadata_fd, &st);
  size_t metadata_size = st.st_size;

  // Start: Read capacity file
  m_max_size = version_capacity(version_metadata_path);

  size_t num_blocks = m_max_size / file_granularity;

  // allocate virtual memory region
  int mmap_flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE;
  if (addr != nullptr)
  {
    mmap_flags |= MAP_FIXED;
  }

  m_addr = mmap(addr, m_max_size, PROT_NONE, mmap_flags, -1, 0);
  if (m_addr == MAP_FAILED){
    std::cerr << "Privateer373: mmap error - " << strerror(errno)<< std::endl;
    exit(-1);
  }

  assert(m_addr != MAP_FAILED);

  // Initialize regions
  regions = new void*[num_blocks];
  for (size_t i = 0; i < num_blocks; i++){
    if (i < num_blocks_current_size){
      regions[i] = mmap(m_addr + i*file_granularity, file_granularity, PROT_READ | PROT_WRITE, mmap_flags | MAP_FIXED, -1, 0);
      if (regions[i] == MAP_FAILED){
        std::cerr << "Privateer386: mmap error - " << strerror(errno)<< std::endl;
        exit(-1);
      }
    }
    else{
      regions[i] = (size_t) 0;
    }
  }

  //Initialize blocks
  blocks = new std::string[num_blocks];

  // Open and mmap files
  char* metadata_content = new char[metadata_size];
  size_t read = ::pread(metadata_fd, (void*) metadata_content, metadata_size, 0);
  assert(read != (size_t)-1);

  std::string empty_block_hash(HASH_SIZE,'0');
  EMPTY_BLOCK_HASH = empty_block_hash;

  std::string all_hashes(metadata_content, metadata_size);
  uint64_t offset = 0;
  // std::cout << "Privateer: Metadata size = " << metadata_size  << std::endl;
  for (size_t i = 0; i < metadata_size; i += HASH_SIZE){
    // std::cout << "Privateer: Initializing blocks and regions, iteration no. " << i << std::endl;
    std::string block_hash(all_hashes, i, HASH_SIZE);
    blocks[i / HASH_SIZE] = block_hash;
    // std::cout << "After assigning blocks[" << i << "]"<<std::endl;
    if (block_hash.compare(EMPTY_BLOCK_HASH) != 0){
      int block_fd;
      // open and mmap file
      block_fd = block_storage->get_block_fd(block_hash.c_str(), (uint64_t) i / HASH_SIZE);
      if (block_fd == -1){
        std::cerr << "Privateer: Error opening and mapping block " << block_hash << " " << strerror(errno) << std::endl;
      }
      assert(block_fd != -1);

      // Add to hash map block_fds_map
      block_file_exist_map[block_hash] = 1;

      // calculate mmap offset then mmap
      offset = (uint64_t) m_addr + (i / HASH_SIZE)*file_granularity;
      // std::cout << "Privateer: offset = " << (uint64_t) offset <<std::endl;
      int prot_flags = read_only ? PROT_READ : PROT_READ | PROT_WRITE;
      /* temp debug --> */ // int mmap_flags = read_only ? MAP_SHARED | MAP_FIXED : MAP_PRIVATE | MAP_FIXED;
      void* region = mmap((void*) offset, file_granularity, prot_flags, MAP_FIXED | MAP_PRIVATE, block_fd, 0);
      if (region == MAP_FAILED){
        std::cerr << "Privateer458: mmap error - " << strerror(errno)<< std::endl;
        exit(-1);
      }

      assert(region != NULL);
      regions[i / HASH_SIZE] = region;
      int close_ret = ::close(block_fd);
      assert(close_ret == 0);
    }
  }
  delete [] metadata_content;
}

inline void Privateer::open(void *addr, const char *version_metadata_path, const char *new_version_metadata_path)
{
  // Check if datastore exist
  if(!utility::directory_exists(version_metadata_path)){
    std::cerr << "Error: Directory " << version_metadata_path << " does not exists" << std::endl;
    throw "Directory Does Not Exists";
  }

  // Check if new directory exists
  if (utility::directory_exists(new_version_metadata_path)){
    std::cerr << "Error: New version metadata directory already exists" << std::endl;
    exit(-1);
  }

  // Create new directory
  if (!utility::create_directory(new_version_metadata_path)){
    std::cerr << "Privateer: Error creating new version directory" << std::endl;
  }
  // Copy all metadata files
  std::string metadata_file = std::string(version_metadata_path) + "/_metadata";
  std::string size_file = std::string(version_metadata_path) + "/_size";
  std::string blocks_path_file = std::string(version_metadata_path) + "/_blocks_path";

  std::string new_metadata_file = std::string(new_version_metadata_path) + "/_metadata";
  std::string new_size_file = std::string(new_version_metadata_path) + "/_size";
  std::string new_blocks_path_file = std::string(new_version_metadata_path) + "/_blocks_path";

  if (!utility::copy_file(metadata_file.c_str(),new_metadata_file.c_str(), false)){
    std::cerr << "Privateer: Error Copying metada file" << std::endl;
    exit(-1);
  }
  if (!utility::copy_file(size_file.c_str(), new_size_file.c_str(), false)){
    std::cerr << "Privateer: Error Copying size file" << std::endl;
    exit(-1);
  }
  if (!utility::copy_file(blocks_path_file.c_str(), new_blocks_path_file.c_str(), false)){
    std::cerr << "Privateer: Error Copying blocks path file" << std::endl;
    exit(-1);
  }
  // Open new copy

  open(addr, new_version_metadata_path, false);

}

inline bool Privateer::resize(size_t size){

  if (m_read_only){
    std::cerr << "Privateer: Region is read-only" << std::endl;
    return false;
  }

  // No effect if smaller size
  if (size < m_current_size){
    return true;
  }

  size_t extra_size = size - m_current_size;
  size_t starting_region_index = m_current_size / file_granularity;
  size_t num_new_regions = (size_t) ceil(extra_size*1.0 / file_granularity);
  size_t size_ceiled = num_new_regions * file_granularity;
  if (size_ceiled > m_max_size){
    std::cerr << "Privateer: new size is larger than the maximum initial reserved size" << std::endl;
    return false;
  }
  for (size_t i = 0 ; i < num_new_regions; i++){
    size_t starting_index = starting_region_index + i;
    regions[starting_index] = mmap((void*)((uint64_t)m_addr + m_current_size + i*file_granularity), file_granularity, PROT_READ | PROT_WRITE, MAP_ANONYMOUS |MAP_PRIVATE | MAP_FIXED, -1, 0);
    blocks[starting_index] = EMPTY_BLOCK_HASH;
    if (regions[starting_index] == MAP_FAILED){
      std::cerr << "Error: failed to map region: " << starting_index << " - " << strerror(errno) << std::endl;
      return false;
    }
  }
  m_current_size = m_current_size + size_ceiled;
  return true;
}

inline void Privateer::msync(){


  #ifdef USE_PAGEMAP
  msync_pagemap();
  #else
  msync_memcopy();
  #endif

}

inline void Privateer::msync_memcopy()
{
  std::cout << "Using memcopy msync" << std::endl;
  //Do it with memcpy
  int fd = m_fds[0];
  // another mmap
  void* shared = mmap(NULL, m_current_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (shared == NULL) {
    std::cout << "ERROR:  m_data == NULL" << std::endl;
    exit(-1);
  }
  std::cout << "Shared mapping done" << std::endl;

  // memcopy
  char* p = (char*)(m_addr);
  char* s = (char*)shared;
  bool diff = false;
  for (size_t i = 0; i < m_current_size; ++i) {
    if (p[i] != s[i]) {
      s[i] = p[i];
      diff = true;
    }
  }
  std::cout << "memcopy done" << std::endl;

  // msync
  if (diff) { ::msync(s, m_current_size, MS_SYNC); }

  std::cout << "msync done" << std::endl;
  // close mmap
  ::munmap(s, m_current_size);

  // invalidate private mappings
  if (diff) { ::msync(p, m_current_size, MS_INVALIDATE); }
  std::cout << "invalidate done" << std::endl;
  //Validation, Temporarily commented, TODO, change it to multi-file
  // validate();
}

inline void Privateer::msync_pagemap(){
  std::cout << "Starting msync" << std::endl;
  #pragma omp parallel for // firstprivate(block_storage)
  for(uint64_t block_start = (uint64_t)m_addr; block_start < ((uint64_t) m_addr + m_current_size); block_start += file_granularity){
    // std::cout << "msync-ing block: " << (block_start - (uint64_t)m_addr) / file_granularity << std::endl;
    msync_pagemap_block_no_copy( (void*) block_start, file_granularity);
  }
  std::cout << "Done msync blocks" << std::endl;
  update_metadata();
  std::cout << "Done updating metadata" << std::endl;

 // Validate: Temporarily commented

  // size_t num_regions = m_current_size / file_granularity;
  /* #pragma omp parallel for
  for(int i = 0 ; i < num_regions ; i++){
    // if (blocks_fds_map.find(blocks[i]) != blocks_fds_map.end()){
    if (blocks[i].compare(EMPTY_BLOCK_HASH) != 0){
      std::string file_path = blocks_dir_path + "/" + blocks[i];
      int fd = ::open(file_path.c_str(), O_RDWR | O_EXCL, (mode_t) 0666);
      assert(fd != -1);
      // std::cout << "Privateer: file desriptor " << fd << std::endl;
      validate(i, fd);
      int close_ret = close(fd);
    }
  } */
  // std::cout << "Privateer: msync completed successfully" << std::endl;

}


inline void Privateer::msync_pagemap_block_no_copy(void* block_start, size_t block_size){

  BlockStorage block_storage_local(*block_storage);
  size_t file_index = ((uint64_t) block_start - (uint64_t) m_addr) / file_granularity;

  uint64_t pagesize = sysconf(_SC_PAGE_SIZE);
  char* start = (char*) block_start;
  double get_pagemap_data_start = omp_get_wtime();

  uint64_t * pagemap_raw_data = utility::read_raw_pagemap(block_start, block_size);
  double get_pagemap_data_end = omp_get_wtime();
  double total_time = get_pagemap_data_end - get_pagemap_data_start;
  /* std::stringstream pagemap_time_stream;
  pagemap_time_stream << "Thread ID: " << omp_get_thread_num() << " read_pagemap_time = " << total_time << std::endl;
  std::cout << pagemap_time_stream; */

  bool in_dirty_block = false;
  uint64_t write_start;
  uint64_t write_count;

  uint64_t dirty_page_count = 0;

  int block_fd = -1;

  std::string temporary_file_name_template = "";
  // std::string existing_block_file_name = "";
  bool write_block_fd = false;

  for (size_t page_index = 0; page_index < (block_size / pagesize); page_index++){

      uint64_t pagemap_raw_data_entry = pagemap_raw_data[page_index];
      utility::PagemapEntry pme = utility::parse_pagemap_entry(pagemap_raw_data_entry);

      if(!pme.file_page && (pme.present || pme.swapped)){
        dirty_page_count++;
        // std::cout << "Privateer: Dirty page with index " << page_index << std::endl;
        if(!in_dirty_block){
          in_dirty_block = true;
          write_start = ((uint64_t) block_start) + page_index * pagesize;
          write_count = pagesize;
        }
        else{
          write_count += pagesize;
        }

        if(page_index == (block_size / pagesize - 1)){
            // open temporary file
            if (block_fd == -1){
              temporary_file_name_template = std::to_string(file_index) + "_temp_XXXXXX";
              char* name_template = (char*) temporary_file_name_template.c_str();
              // std::cout << "Privateer: temporary file name = " << name_template << std::endl;
              std::string block_hash = blocks[file_index];
              if (block_hash.compare(EMPTY_BLOCK_HASH) != 0){
                // existing_block_file_name =  block_storage->get_blocks_subdirectory(file_index) + "/" + block_hash;
                // copy
                /* std::stringstream copy_stream;
                copy_stream << "Thread ID: " << omp_get_thread_num() << " Privateer: Copying existing file " << std::endl;
                std::cout << copy_stream.str();*/ // "Privateer: Copying existing file" << std::endl;
                block_fd = block_storage_local.create_temporary_unique_block(name_template, file_index); // , existing_block_file_name.c_str());
                if (block_fd == -1){
                  std::cerr << "Privateer: Error creating temporary file"<< std::endl;
                  exit(-1);
                }
                write_block_fd = true;
                break;
              }
              else{
                block_fd = block_storage_local.create_temporary_unique_block(name_template, file_index);
                if (block_fd == -1){
                  std::cerr << "Privateer: Error creating temporary file"<< std::endl;
                  exit(-1);
                }
              }
            }

          // writeback
          // std::cout << "Privateer: Writing from block  " << (uint64_t) write_start << std::endl;
          // std::cout << "Privateer: Writing " << write_count << "bytes" << std::endl;
          const auto written = ::pwrite(block_fd ,(void*) write_start, write_count, write_start - (uint64_t) block_start);

          if (written == -1){
            std::cerr << "Error: Failed to write page with address: " << std::to_string(write_start) << std::endl;
            exit(-1); // return;
          }
        }
      }
      else if(in_dirty_block){

        // open temporary file
        if (block_fd == -1){
          temporary_file_name_template = std::to_string(file_index) + "_temp_XXXXXX";
          char* name_template = (char*) temporary_file_name_template.c_str();
          std::string block_hash = blocks[file_index];
          if (block_hash.compare(EMPTY_BLOCK_HASH) != 0){
            // existing_block_file_name = block_storage->get_blocks_subdirectory(file_index) + "/" + block_hash;

            block_fd = block_storage_local.create_temporary_unique_block(name_template, file_index); //, existing_block_file_name.c_str());
            if (block_fd == -1){
              std::cerr << "Privateer: Error creating temporary file"<< std::endl;
              exit(-1);
            }
            write_block_fd = true;
            break;
          }
          else{
            block_fd = block_storage_local.create_temporary_unique_block(name_template, file_index);
            if (block_fd == -1){
              std::cerr << "Privateer: Error creating temporary file"<< std::endl;
              exit(-1);
            }
          }
        }
        // writeback
        // std::cout << "Privateer: Writing from block  " << (uint64_t) write_start << std::endl;
        // std::cout << "Privateer: Writing " << write_count << "bytes" << std::endl;
        const auto written = ::pwrite(block_fd ,(void*) write_start, write_count, write_start - (uint64_t) block_start);
        if (written == -1){
          std::cerr << "Error: Failed to write page with address: " << std::to_string(write_start) << std::endl;
          return;
        }
        in_dirty_block = false;
      }
    }

    if (block_fd != -1){
      bool status = block_storage_local.store_block(block_fd, start, write_block_fd, file_index);
      if (!status){
        std::cerr << "Privateer: Error storing block with index " << file_index << std::endl;
        exit(-1);
      }
      // mmap new file
      regions[file_index] = mmap((void*)block_start, file_granularity, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, block_fd, 0);
      if (regions[file_index] == MAP_FAILED){
        std::cerr << "Privateer797: mmap error - " << strerror(errno)<< std::endl;
        exit(-1);
      }
      assert(regions[file_index] != MAP_FAILED);
      // update blocks_fds_map, blocks, and regions if needed.
      std::string block_hash = std::string(block_storage_local.get_block_hash(block_fd));
      block_file_exist_map[block_hash] = 1; // block_fd;
      blocks[file_index] = block_hash;
      // close file
      int close_ret = close(block_fd);
      assert(close_ret != -1);
    }

    // TODO: Re-map the file to discard page cache?
  size_t total_size = dirty_page_count*pagesize;

  delete [] pagemap_raw_data;
}


bool Privateer::snapshot(const char* version_metadata_path){
  // Create new version metadata directory
  if(utility::directory_exists(version_metadata_path)){
    std::cerr << "Error: Version metadata directory already exists" << std::endl;
    return false;
  }

  if (!utility::create_directory(version_metadata_path)){
    std::cerr << "Error: Failed to create version metadata directory" << std::endl;
  }

  // temporarily change metadata file descriptor
  int temp_metada_fd = metadata_fd;
  std::string snapshot_metadata_path = std::string(version_metadata_path) + "/_metadata";
  // std::cout << "Privateer: Snapshotting to " << snapshot_metadata_path << std::endl;
  metadata_fd = ::open(snapshot_metadata_path.c_str(), O_RDWR | O_CREAT, (mode_t) 0666);
  assert(metadata_fd != -1);
  msync();
  metadata_fd = temp_metada_fd;

  // Create file to save blocks path
  std::string blocks_path_file_name = std::string(version_metadata_path) + "/_blocks_path";
  std::ofstream blocks_path_file;
  blocks_path_file.open(blocks_path_file_name);
  blocks_path_file << blocks_dir_path;
  blocks_path_file.close();

  // Create file to save current size
  std::string size_path_file_name = std::string(version_metadata_path) + "/_size";
  std::ofstream size_path_file;
  size_path_file.open(size_path_file_name);
  size_path_file << m_current_size;
  size_path_file.close();


  // Create file to save max. capacity
  std::string capacity_path_file_name = std::string(version_metadata_path) + "/_capacity";
  std::ofstream capacity_path_file;
  capacity_path_file.open(capacity_path_file_name);
  capacity_path_file << m_max_size;
  capacity_path_file.close();

  return true;
}

inline void Privateer::validate(int region_index, int fd)
{
  char *v_addr = (char *)mmap(nullptr, file_granularity, PROT_READ, MAP_SHARED, fd, 0);
  assert(v_addr != MAP_FAILED);
  char *d_addr = (char *) regions[region_index];

  for (size_t i = 0; i < file_granularity; ++i)
  {
    assert(v_addr[i] == d_addr[i]);
  }
  // std::cout << "Validation done" << std::endl;
  int ret = munmap(v_addr, file_granularity);
  assert(ret == 0);
  // std::cout << "unmapping done" << std::endl;
}

inline void Privateer::update_metadata(){

  // std::cout << "Privateer: update metadata m_current_size = " << m_current_size << std::endl;
  // std::cout << "Privateer: update metadata m_max_size = " << m_max_size << std::endl;
  size_t num_blocks = m_current_size / file_granularity;
  size_t current_size = 0;
  char* blocks_bytes = new char[num_blocks*HASH_SIZE];
  for (size_t i = 0 ; i < num_blocks ; i++){
    const char* block_hash_bytes = blocks[i].c_str();
    if (blocks[i].compare(EMPTY_BLOCK_HASH) != 0){
      current_size = (i+1)*file_granularity;
    }
    for (int j = 0; j < HASH_SIZE; j++){
      blocks_bytes[i*HASH_SIZE + j] = block_hash_bytes[j];
    }
  }

  // Update metadata file
  const auto written = ::pwrite(metadata_fd ,(void*) blocks_bytes, num_blocks*HASH_SIZE, 0);
  if (written == -1){
    std::cerr << "Error, failed to update metadata and mappings: " << strerror(errno) << std::endl;
  }
  assert(written != -1);

  // Update size file
  // Create size file
  // m_current_size = current_size;
  // std::cout << "Privateer: m_current_size in update_metadata() = " << m_current_size << std::endl;
  std::string size_file_name = std::string(version_metadata_dir_path) + "/_size";
  // std::cout << "Privateer: update_metadata() size_file_name = " << size_file_name << std::endl;
  std::ofstream size_file(size_file_name, std::ios::trunc);
  if (!size_file.good()){
    std::cerr << "Privateer: Error updaging metadata size file - " << strerror(errno) << std::endl;
    exit(-1);
  }
  size_file << m_current_size;
  size_file.close();
  delete [] blocks_bytes;

}

inline Privateer::~Privateer()
{
  void* status = mmap(m_addr, m_current_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (status == MAP_FAILED){
    std::cerr << "Privateer: Error releasing region" << std::endl;
    exit(-1);
  }
  /* std::cout << "Privateer: Destroying Privateer Object" << std::endl;
  int ret = munmap(m_addr, m_max_size);
  if (ret != 0){
    std::cerr << "Privateer: Error unmapping max size original" << std::endl;
    exit(-1);
  }

  std::cout << "Done unmapping max size" << std::endl;
  // munmap all regions and free memory
  int num_regions = m_current_size / file_granularity;
  for (int i = 0; i < num_regions; i++){
    if (regions[i] != (size_t) 0){
      ret = munmap(regions[i], file_granularity);
      if (ret != 0){
        std::cerr << "Privateer: Error unmapping max size original" << std::endl;
        exit(-1);
      }
    }
  } */
  std::cout << "Done unmapping regions" << std::endl;
  delete [] regions;
  std::cout << "Done deleting regions" << std::endl;
  // close all files and free memory
  /* for(int i = 0; i < num_regions; i++){
    int fd = blocks_fds_map[blocks[i]];
    if (fd > 1){
      ret = close(fd);
      assert(ret == 0);
      blocks_fds_map[blocks[i]] = -1;
    }
  } */
  delete [] blocks;
  std::cout << "Done deleting blocks" << std::endl;
  delete block_storage;
  std::cout << "Done deleting block storage" << std::endl;
  int close_metadata = ::close(metadata_fd);
  std::cout << "Privateer: Object destroyed successfully" << std::endl;
}

inline void* Privateer::data(){
  return m_addr;
}

inline size_t Privateer::current_size(){
  return m_current_size;
}

inline size_t Privateer::max_size(){
  return m_max_size;
}

inline size_t Privateer::version_size(std::string version_path){
  // Read size path
  std::string size_string;
  std::string size_file_name = std::string(version_path) + "/_size";
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
