// Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
// See the top-level LICENSE file for details.
//
// SPDX-License-Identifier: MIT

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

#include "utility/sha256_hash.hpp"
#include "utility/file_util.hpp"
#include "utility/system.hpp"

class BlockStorage
{
  public:
    BlockStorage(std::string base_directory);
    BlockStorage(std::string base_directory, size_t block_granularity);
    BlockStorage(const BlockStorage &block_storage);
    ~BlockStorage();

    int create_temporary_unique_block(char* name_template, uint64_t file_index);
    int create_temporary_unique_block(char* name_template, const char* original_path, uint64_t file_index);
    bool store_block(int fd, void* buffer, bool write_file, uint64_t file_index);
    int get_block_fd(const char* hash, uint64_t file_index);
    char* get_block_hash(int fd);
    size_t get_block_granularity();
    std::string get_blocks_subdirectory(uint64_t file_index);

  private:
    std::string base_directory;
    size_t block_granularity;
    std::map<int, std::string> block_fd_hash;
    std::map<int, std::string> block_fd_temp_name;
    bool block_exists(const char* hash);
    // std::mutex * store_block_mutex;
    // bip::named_mutex *store_block_mutex; // (bip::open_or_create, "store_block_mutex");
    std::mutex create_block_directory_mutex;
    size_t files_per_subdirectory = 1024;
    // std::atomic<size_t> num_files = 0;
};

BlockStorage::BlockStorage(std::string base_directory_path){
  if(!utility::directory_exists(base_directory_path.c_str())){
    std::cerr << "BlockStorage: Error - Blocks directory does not exist" << std::endl;
    exit(-1);
  }
  // std::cout << "BlockStorage: Base directory path arg = " << base_directory_path << std::endl;
  base_directory = base_directory_path;
  // std::cout << "BlockStorage: Base directory path = " << base_directory << std::endl;

  std::string granularity_string;
  std::string granularity_file_name = base_directory + "/_granularity";
  std::ifstream granularity_file;
  granularity_file.open(granularity_file_name);
  if (!granularity_file.is_open()){
    std::cerr << "BlockStorage: Error opening block granularity metadata"<< std::endl;
    exit(-1);
  }
  if (!std::getline(granularity_file, granularity_string)){
    std::cerr << "BlockStorage: Error reading block granularity metadata"<< std::endl;
    exit(-1);
  }
  block_granularity = std::stol(granularity_string);
  // store_block_mutex =  new std::mutex(); // bip::named_mutex(bip::open_or_create, "store_block_mutex");
  // std::cout << "BlockStorage: Base directory path = " << base_directory << std::endl;
}

BlockStorage::BlockStorage(std::string base_directory_path, const size_t block_granularity_arg){
  // std::cout << "BlockStorage: Base directory path arg = " << base_directory_path << std::endl;
  base_directory = base_directory_path;
  // std::cout << "BlockStorage: Base directory path = " << base_directory << std::endl;

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
      std::cerr << "BlockStorage: Error - Blocks directory already exists" << std::endl;
      exit(-1);
    }
  // }
  /* else{
    std::cerr << "BlockStorage: Error -  Blocks directory already exists" << std::endl;
    exit(-1);
  } */
  // store_block_mutex =  new std::mutex(); // bip::named_mutex(bip::open_or_create, "store_block_mutex");
}

// Copy Constructor
BlockStorage::BlockStorage(const BlockStorage &block_storage){
  // std::cout << "BlockStorage: Calling Copy Constructor" << std::endl;
  base_directory = block_storage.base_directory;
  block_granularity = block_storage.block_granularity;
  block_fd_hash = block_storage.block_fd_hash;
  block_fd_temp_name = block_storage.block_fd_temp_name;
  // store_block_mutex =  new std::mutex();// block_storage.store_block_mutex; // new bip::named_mutex(bip::open_or_create, "store_block_mutex");
  /* store_block_mutex = block_storage.store_block_mutex;
  create_block_directory_mutex = block_storage.create_block_directory_mutex; */
}



BlockStorage::~BlockStorage(){
  // bip::named_mutex::remove("store_block_mutex");
  // delete store_block_mutex;
}

int BlockStorage::create_temporary_unique_block(char* name_template, uint64_t file_index){
  // std::lock_guard<std::mutex> store_lock(store_block_mutex);
  std::string subdirectory_name = get_blocks_subdirectory(file_index);
  std::string temporary_file_name = subdirectory_name + "/" + std::string(name_template);
  char* temporary_file_name_template = new char[temporary_file_name.length() + 1];
  temporary_file_name_template = (char*) memcpy((void*) temporary_file_name_template, (void*) temporary_file_name.c_str(), temporary_file_name.length() + 1);
  // std::cout << "BlockStorage: temporary_file_name_template =" << temporary_file_name_template << std::endl;
  int fd = mkstemp(temporary_file_name_template);
  if (fd == -1){
    std::cerr << "BlockStorage: Error creating temporary file" << strerror(errno) << std::endl;
    return fd;
  }
  // std::cout << "BlockStorage: block_granularity = " << block_granularity << std::endl;
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


int BlockStorage::create_temporary_unique_block(char* name_template, const char* original_path, uint64_t file_index){
  std::string subdirectory_name = get_blocks_subdirectory(file_index);
  std::string temporary_file_name = subdirectory_name + "/" + std::string(name_template);
  char* temporary_file_name_template = new char[temporary_file_name.length() + 1];
  temporary_file_name_template = (char*) memcpy((void*) temporary_file_name_template, (void*) temporary_file_name.c_str(), temporary_file_name.length() + 1);
  // std::cout << "BlockStorage: temporary_file_name_template =" << temporary_file_name_template << std::endl;
  // std::cout << "BlockStorage: Original path = " << original_path << std::endl;
  int fd = mkstemp(temporary_file_name_template);
  // std::cout << "BlockStorage: temporary_file_name_template =" << temporary_file_name_template << std::endl;
  if (fd == -1){
    std::cerr << "BlockStorage: Error creating temporary file" << strerror(errno) << std::endl;
    return fd;
  }
  // std::cout << "BlockStorage: block_granularity = " << block_granularity << std::endl;
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

bool BlockStorage::store_block(int fd, void* buffer, bool write_to_file, uint64_t file_index){
  if (block_fd_temp_name.find(fd) == block_fd_temp_name.end()){
    std::cerr << "BlockStorage: Error - No open file descriptor for this block" << std::endl;
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

  // std::cout << "BlockStorage: store_block() base_directory = " << base_directory << std::endl;
  // std::cout << "BlockStorage: store_block() std::string(base_directory) returns  " << std::string(base_directory) << std::endl;

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
          std::cerr << "BlockStorage: Error writing to file" << std::endl;
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
            std::cerr << "BlockStorage: Error removing temporary file" << std::endl;
            return false;
          }
          return true;
        }
        else{
          std::cerr << "BlockStorage: Error renaming file " << strerror(errno) << std::endl;
          std::cerr << "Temporary file name = " << temporary_filename << std::endl;
        }
        return false;
      }
    }
    else{
      int remove_status = remove(temporary_filename.c_str());
      if (remove_status != 0){
        std::cerr << "BlockStorage: Error removing temporary file" << std::endl;
        return false;
      }
    }
  // }
  /* else{
    int remove_status = remove(temporary_filename.c_str());
    if (remove_status != 0){
      std::cerr << "BlockStorage: Error removing temporary file" << std::endl;
      return false;
    }
  } */
  return true;
}

int BlockStorage::get_block_fd(const char* hash, uint64_t file_index){
  std::string subdirectory_name = get_blocks_subdirectory(file_index);
  std::string filename = subdirectory_name + "/" + std::string(hash);
  int block_fd = ::open(filename.c_str(), O_RDONLY, (mode_t) 0666);
  return block_fd;
}

char* BlockStorage::get_block_hash(int fd){
  if (block_fd_hash.find(fd) == block_fd_hash.end()){
    std::string empty_string = "";
    return (char*) empty_string.c_str();
  }
  else{
    return (char*) block_fd_hash[fd].c_str();
  }
}

size_t BlockStorage::get_block_granularity(){
  return block_granularity;
}

std::string BlockStorage::get_blocks_subdirectory(uint64_t file_index){
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
