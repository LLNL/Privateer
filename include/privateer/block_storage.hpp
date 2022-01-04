// Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
// See the top-level LICENSE file for details.
//
// SPDX-License-Identifier: MIT

#pragma once

#include <filesystem>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <cerrno>
#include <atomic>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include "boost/lexical_cast.hpp"

#include "utility/sha256_hash.hpp"
#include "utility/file_util.hpp"
#include "utility/system.hpp"

class block_storage
{
  public:
    block_storage(std::string base_directory); // Open
    block_storage(std::string base_directory, std::string stash_directory); // Open with Stash
    block_storage(std::string base_directory, size_t block_granularity); // Create
    block_storage(std::string base_directory, std::string stash_directory, size_t block_granularity); // Create with Stash

    block_storage(const block_storage &block_storage);
    ~block_storage();

    int create_temporary_unique_block(char* name_template, uint64_t file_index);
    int create_temporary_unique_block(char* name_template, const char* original_path, uint64_t file_index);
    bool store_block(int fd, void* buffer, bool write_file, uint64_t file_index);
    bool stash_block(void* block_start, uint64_t block_index);
    std::string commit_stash_block(void* block_start, uint64_t block_index);
    int get_block_fd(const char* hash, uint64_t file_index);
    char* get_block_hash(int fd);
    size_t get_block_granularity();
    std::string get_blocks_subdirectory(uint64_t file_index);
    std::string get_block_stash_path(size_t block_index);
    std::string get_blocks_path();

  private:
    void create(std::string base_directory, std::string stash_directory, size_t block_granularity);
    void open(std::string base_directory, std::string stash_directory);
    std::string base_directory;
    std::string stash_directory;
    size_t block_granularity;
    std::map<int, std::string> block_fd_hash;
    std::map<int, std::string> block_fd_temp_name;
    std::map<uint64_t, std::string> stash_block_ids;
    bool block_exists(const char* hash);
    // std::mutex * store_block_mutex;
    // bip::named_mutex *store_block_mutex; // (bip::open_or_create, "store_block_mutex");
    std::mutex create_block_directory_mutex;
    size_t files_per_subdirectory = 1024;
    // std::atomic<size_t> num_files = 0;
};

block_storage::block_storage(std::string base_directory_path){
  open(base_directory_path,"");
}

block_storage::block_storage(std::string base_directory_path, std::string stash_directory){
  open(base_directory_path,stash_directory);
}

block_storage::block_storage(std::string base_directory_path, const size_t block_granularity_arg){
  create(base_directory_path, "", block_granularity_arg);
}

block_storage::block_storage(std::string base_directory_path, std::string stash_directory_path, const size_t block_granularity_arg){
  create(base_directory_path, stash_directory, block_granularity_arg);
}

// Copy Constructor
block_storage::block_storage(const block_storage &block_storage){
  // std::cout << "block_storage: Calling Copy Constructor" << std::endl;
  base_directory = block_storage.base_directory;
  block_granularity = block_storage.block_granularity;
  block_fd_hash = block_storage.block_fd_hash;
  block_fd_temp_name = block_storage.block_fd_temp_name;
  // store_block_mutex =  new std::mutex();// block_storage.store_block_mutex; // new bip::named_mutex(bip::open_or_create, "store_block_mutex");
  /* store_block_mutex = block_storage.store_block_mutex;
  create_block_directory_mutex = block_storage.create_block_directory_mutex; */
}

block_storage::~block_storage(){
  // bip::named_mutex::remove("store_block_mutex");
  // delete store_block_mutex;
}

void block_storage::create(std::string base_directory_path, std::string stash_directory_path, size_t block_granularity_arg){
  if (!stash_directory.empty()){
    // Create stash directory
    if (utility::directory_exists(stash_directory_path.c_str())){
      std::cerr << "Error: Stash directory already exists" << std::endl;
      exit(-1);
    }
    if (!utility::create_directory(stash_directory_path.c_str())){
      std::cerr << "Error: Failed to create stash directory" << std::endl;
      exit(-1);
    }
  }
  // std::cout << "block_storage: Base directory path arg = " << base_directory_path << std::endl;
  base_directory = base_directory_path;
  // std::cout << "block_storage: Base directory path = " << base_directory << std::endl;

  stash_directory = stash_directory_path;

  block_granularity = block_granularity_arg;

  //  if (!utility::directory_exists(base_directory_path.c_str())){
  // Grab mutex
  // std::lock_guard<std::mutex> create_blocks_dir_lock(create_block_directory_mutex);
  if (!utility::directory_exists(base_directory_path.c_str())){
    // create blocks directory and save block_granularity in _metadata
    if (!utility::create_directory(base_directory.c_str())){
      std::cerr << "Error: Failed to create blocks directory" << std::endl;
      exit(-1);
    }
    std::string granularity_file_name = base_directory + "/_granularity";
    std::ofstream granularity_file;
    granularity_file.open(granularity_file_name);
    granularity_file << block_granularity;
    granularity_file.close();
  }
  else{
    std::cerr << "block_storage: Error - Blocks directory already exists" << std::endl;
    exit(-1);
  }
}

void block_storage::open(std::string base_directory_path, std::string stash_directory_path){
  if (!stash_directory.empty()){
    // Create stash directory
    if (utility::directory_exists(stash_directory_path.c_str())){
      std::cerr << "Error: Stash directory already exists" << std::endl;
      exit(-1);
    }
    if (!utility::create_directory(stash_directory_path.c_str())){
      std::cerr << "Error: Failed to create stash directory" << std::endl;
      exit(-1);
    }
  }
  if(!utility::directory_exists(base_directory_path.c_str())){
    std::cerr << "block_storage: Error - Blocks directory does not exist" << std::endl;
    exit(-1);
  }
  // std::cout << "block_storage: Base directory path arg = " << base_directory_path << std::endl;
  base_directory = base_directory_path;
  // std::cout << "block_storage: Base directory path = " << base_directory << std::endl;

  stash_directory = stash_directory_path;

  std::string granularity_string;
  std::string granularity_file_name = base_directory + "/_granularity";
  std::ifstream granularity_file;
  granularity_file.open(granularity_file_name);
  if (!granularity_file.is_open()){
    std::cerr << "block_storage: Error opening block granularity metadata"<< std::endl;
    exit(-1);
  }
  if (!std::getline(granularity_file, granularity_string)){
    std::cerr << "block_storage: Error reading block granularity metadata"<< std::endl;
    exit(-1);
  }
  block_granularity = std::stol(granularity_string);
  // store_block_mutex =  new std::mutex(); // bip::named_mutex(bip::open_or_create, "store_block_mutex");
  // std::cout << "block_storage: Base directory path = " << base_directory << std::endl;
}

int block_storage::create_temporary_unique_block(char* name_template, uint64_t file_index){
  // std::lock_guard<std::mutex> store_lock(store_block_mutex);
  std::string subdirectory_name = get_blocks_subdirectory(file_index);
  std::string temporary_file_name = subdirectory_name + "/" + std::string(name_template);
  char* temporary_file_name_template = new char[temporary_file_name.length() + 1];
  temporary_file_name_template = (char*) memcpy((void*) temporary_file_name_template, (void*) temporary_file_name.c_str(), temporary_file_name.length() + 1);
  // std::cout << "block_storage: temporary_file_name_template =" << temporary_file_name_template << std::endl;
  int fd = mkstemp(temporary_file_name_template);
  if (fd == -1){
    std::cerr << "block_storage: Error creating temporary file" << strerror(errno) << std::endl;
    return fd;
  }
  // std::cout << "block_storage: block_granularity = " << block_granularity << std::endl;
  int trunc_status = ftruncate(fd, block_granularity);
  if (trunc_status == -1){
    std::cerr << "Block Storage: Error sizing file" << std::endl;
    return -1;
  }
  if (block_fd_temp_name.find(fd) == block_fd_temp_name.end()){
    block_fd_temp_name.insert(std::pair<int, std::string>(fd, std::string(temporary_file_name_template)));
  }
  else{
    block_fd_temp_name[fd] = temporary_file_name_template;
  }
  delete temporary_file_name_template;
  return fd;
}


int block_storage::create_temporary_unique_block(char* name_template, const char* original_path, uint64_t file_index){
  std::string subdirectory_name = get_blocks_subdirectory(file_index);
  std::string temporary_file_name = subdirectory_name + "/" + std::string(name_template);
  char* temporary_file_name_template = new char[temporary_file_name.length() + 1];
  temporary_file_name_template = (char*) memcpy((void*) temporary_file_name_template, (void*) temporary_file_name.c_str(), temporary_file_name.length() + 1);
  // std::cout << "block_storage: temporary_file_name_template =" << temporary_file_name_template << std::endl;
  // std::cout << "block_storage: Original path = " << original_path << std::endl;
  int fd = mkstemp(temporary_file_name_template);
  // std::cout << "block_storage: temporary_file_name_template =" << temporary_file_name_template << std::endl;
  if (fd == -1){
    std::cerr << "block_storage: Error creating temporary file" << strerror(errno) << std::endl;
    return fd;
  }
  // std::cout << "block_storage: block_granularity = " << block_granularity << std::endl;
  int trunc_status = ftruncate(fd, block_granularity);
  if (trunc_status == -1){
    std::cerr << "Block Storage: Error sizing file" << std::endl;
    return -1;
  }
  if (!utility::copy_file(original_path, temporary_file_name_template, true)){
    std::cerr << "Block Storage: Error copying file - " << original_path << std::endl;
    return -1;
  }
  if (block_fd_temp_name.find(fd) == block_fd_temp_name.end()){
    block_fd_temp_name.insert(std::pair<int, std::string>(fd, std::string(temporary_file_name_template)));
  }
  else{
    block_fd_temp_name[fd] = temporary_file_name_template;
  }
  delete temporary_file_name_template;
  return fd;
}

bool block_storage::store_block(int fd, void* buffer, bool write_to_file, uint64_t file_index){
  if (block_fd_temp_name.find(fd) == block_fd_temp_name.end()){
    std::cerr << "block_storage: Error - No open file descriptor for this block" << std::endl;
    std::cerr << "fd = " << fd << std::endl;
    return false;
  }

  std::string subdirectory_name = get_blocks_subdirectory(file_index);
  std::string block_hash = utility::compute_hash((char*) buffer, block_granularity);
  if ( block_fd_hash.find(fd) ==  block_fd_hash.end()){
    block_fd_hash.insert(std::pair<int, std::string>(fd, std::string(block_hash)));
  }
  else{
    block_fd_hash[fd] = std::string(block_hash);
  }

  // std::cout << "block_storage: store_block() base_directory = " << base_directory << std::endl;
  // std::cout << "block_storage: store_block() std::string(base_directory) returns  " << std::string(base_directory) << std::endl;

  std::string final_filename = subdirectory_name + "/" + block_hash;
  std::string temporary_filename = block_fd_temp_name[fd];

  // Check if file exists
  // if (!utility::file_exists(final_filename.c_str())){
    // std::lock_guard<std::mutex> store_lock(*store_block_mutex);
    // bip::scoped_lock<bip::named_mutex> lock(*store_block_mutex);
    if (!utility::file_exists(final_filename.c_str())){
      // Write
      if (write_to_file){
        size_t written = pwrite(fd ,buffer, block_granularity, 0);
        if (written == -1){
          std::cerr << "block_storage: Error writing to file" << std::endl;
          // store_block_mutex->unlock();
          return false;
        }
      }
      // Rename
      // std::cout << "temporary_filename = " << temporary_filename << std::endl;
      // std::cout << "final_filename = " << final_filename << std::endl;
      int rename_status = rename(temporary_filename.c_str(),final_filename.c_str());
      if (rename_status != 0){
        if (utility::file_exists(final_filename.c_str())){
          int remove_status = remove(temporary_filename.c_str());
          if (remove_status != 0){
            std::cerr << "block_storage: Error removing temporary file" << std::endl;
            return false;
          }
          return true;
        }
        else{
          std::cerr << "block_storage: Error renaming file " << strerror(errno) << std::endl;
          std::cerr << "Temporary file name = " << temporary_filename << std::endl;
        }
        return false;
      }
    }
    else{
      int remove_status = remove(temporary_filename.c_str());
      if (remove_status != 0){
        std::cerr << "block_storage: Error removing temporary file" << std::endl;
        return false;
      }
    }
  // }
  /* else{
    int remove_status = remove(temporary_filename.c_str());
    if (remove_status != 0){
      std::cerr << "block_storage: Error removing temporary file" << std::endl;
      return false;
    }
  } */
  return true;
}

bool block_storage::stash_block(void* block_start, uint64_t block_index){
  boost::uuids::uuid uuid = boost::uuids::random_generator()();
  const std::string block_UUID = boost::lexical_cast<std::string>(uuid);
  std::string block_temp_path = stash_directory + "/" + block_UUID;
  int block_fd = ::open(block_temp_path.c_str(), O_CREAT, O_RDWR);
  if (block_fd == -1){
    std::cerr << "block_storage: Error opening stash file descriptor - " << strerror(errno) << std::endl;
    return false;
  }
  if (pwrite(block_fd, block_start, block_granularity, 0) == -1){
    std::cerr << "block_storage: Error writing block to stash file - " << strerror(errno) << std::endl;
    return false;
  }
  // Add to/update stash lookup
  stash_block_ids[block_index] = block_UUID;
}

// [In-Progress]
std::string block_storage::commit_stash_block(void* block_start, uint64_t block_index){
  // Compute block hash
  std::string subdirectory_name = get_blocks_subdirectory(block_index);
  std::string block_hash = utility::compute_hash((char*) block_start, block_granularity);

  // Rename block
  std::string final_filename = subdirectory_name + "/" + block_hash;
  std::string stash_filename = stash_directory + "/" + stash_block_ids[block_index];

  if (!utility::file_exists(final_filename.c_str())){
    
    // Rename
    int rename_status = rename(stash_filename.c_str(),final_filename.c_str());
    if (rename_status != 0){
      if (utility::file_exists(final_filename.c_str())){
        int remove_status = remove(stash_filename.c_str());
        if (remove_status != 0){
          std::cerr << "block_storage: Error removing stash file" << std::endl;
          return "";
        }
        return block_hash;
      }
      else{
        std::cerr << "block_storage: Error renaming file " << strerror(errno) << std::endl;
        std::cerr << "Stash file name = " << stash_filename << std::endl;
      }
      return "";
    }
  }
  else{
    int remove_status = remove(stash_filename.c_str());
    if (remove_status != 0){
      std::cerr << "block_storage: Error removing stash file" << std::endl;
      return "";
    }
    return block_hash;
  }

}

int block_storage::get_block_fd(const char* hash, uint64_t file_index){
  std::string subdirectory_name = get_blocks_subdirectory(file_index);
  std::string filename = subdirectory_name + "/" + std::string(hash);
  int block_fd = ::open(filename.c_str(), O_RDONLY, (mode_t) 0666);
  return block_fd;
}

char* block_storage::get_block_hash(int fd){
  if (block_fd_hash.find(fd) == block_fd_hash.end()){
    std::string empty_string = "";
    return (char*) empty_string.c_str();
  }
  else{
    return (char*) block_fd_hash[fd].c_str();
  }
}

size_t block_storage::get_block_granularity(){
  return block_granularity;
}

std::string block_storage::get_blocks_subdirectory(uint64_t file_index){
  size_t subdir_index = file_index % files_per_subdirectory;
  std::string subdir_name = base_directory + "/" + std::to_string(subdir_index);
  if (!utility::directory_exists(subdir_name.c_str())){
    if (!utility::create_directory(subdir_name.c_str())){
        std::cerr << "Error: Failed to create blocks subdirectory" << std::endl;
        exit(-1);
    }
  }

  return subdir_name;
}

std::string block_storage::get_block_stash_path(size_t block_index){
  std::string block_stash_path = "";
  if (stash_block_ids.find(block_index) != stash_block_ids.end()){
    block_stash_path = stash_directory + "/" + stash_block_ids[block_index];
  }
  return block_stash_path;
}

std::string block_storage::get_blocks_path(){
  return base_directory;
}
