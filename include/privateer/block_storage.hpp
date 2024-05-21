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
#include <string>


#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include "boost/lexical_cast.hpp"

#include "utility/sha256_hash.hpp"
#include "utility/file_util.hpp"
#include "utility/system.hpp"
#ifdef USE_COMPRESSION
#include "utility/compression.hpp"
#endif

class block_storage
{
  public:
    // Open
    block_storage(std::string base_directory){
      open(base_directory,"");
    } 

    // Open with Stash
    block_storage(std::string base_directory, std::string stash_directory){
      open(base_directory, stash_directory);
    }

    // Create
    block_storage(std::string base_directory, size_t block_granularity){
      create(base_directory, "", block_granularity);
    } 

    // Create with Stash
    block_storage(std::string base_directory, std::string stash_directory, size_t block_granularity_arg){
      create(base_directory, stash_directory, block_granularity_arg);
    }

    block_storage(const block_storage &block_storage){
      // std::cout << "block_storage: Calling Copy Constructor" << std::endl;
      base_directory = block_storage.base_directory;
      block_granularity = block_storage.block_granularity;
      // block_fd_hash = block_storage.block_fd_hash;
      // block_fd_temp_name = block_storage.block_fd_temp_name;
      stash_directory = block_storage.stash_directory;
      stash_block_ids = block_storage.stash_block_ids;
      // store_block_mutex =  new std::mutex();// block_storage.store_block_mutex; // new bip::named_mutex(bip::open_or_create, "store_block_mutex");
      /* store_block_mutex = block_storage.store_block_mutex;
      create_block_directory_mutex = block_storage.create_block_directory_mutex; */
    }

    ~block_storage(){
      // bip::named_mutex::remove("store_block_mutex");
      // delete store_block_mutex;
    }


    std::string store_block(void* buffer, bool write_to_file, uint64_t block_index){
      std::string block_hash = "";
      bool on_stash = is_multi_tiered();
      if (on_stash){
        std::string block_hash = store_block(buffer, write_to_file, block_index, true, "");
        if (block_hash.empty()){
          std::cerr << "block_storage: Error storing block with index: " << block_index << std::endl;
          return block_hash;
        }
        on_stash = false;
      }
      std::string block_hash_final = store_block(buffer, write_to_file, block_index, on_stash, block_hash);
      if (!block_hash_final.empty()){
        stash_committed_block_ids.insert(std::pair<uint64_t,std::string>(block_index, block_hash));
      }
      return block_hash_final;
    }

    bool stash_block(void* block_start, uint64_t block_index){
      // Reusing stash file (mutable)
      std::string block_UUID = "";
      std::string block_temp_path = "";
      bool file_exists = false;
      int block_fd = -1;
      if (stash_block_ids.find(block_index) != stash_block_ids.end()){
        block_UUID = stash_block_ids[block_index];
        file_exists = true;
      }
      else{
        boost::uuids::uuid uuid = boost::uuids::random_generator()();
        block_UUID = boost::lexical_cast<std::string>(uuid);
        stash_block_ids.insert(std::pair<uint64_t,std::string>(block_index, block_UUID));
      }
      block_temp_path = stash_directory + "/" + block_UUID;
      int open_flags = file_exists ? O_RDWR : O_CREAT | O_RDWR;
      block_fd = ::open(block_temp_path.c_str(), open_flags,  S_IRUSR | S_IWUSR);
      if (block_fd == -1){
        std::cerr << "block_storage: Error opening stash file descriptor - " << strerror(errno) << std::endl;
        return false;
      }
      if (!file_exists){
        int trunc_status = ftruncate(block_fd, block_granularity);
        if (trunc_status == -1){
          std::cerr << "Block Storage: Error sizing file - " << strerror(errno) << std::endl;
          return false;
        }
      }
      if (pwrite(block_fd, block_start, block_granularity, 0) == -1){
        std::cerr << "block_storage: Error writing block to stash file - " << strerror(errno) << std::endl;
        return false;
      }
      if (close(block_fd) == -1){
        std::cerr << "block_storage: Error closing stash file: " << strerror(errno) << std::endl;
        return false;
      }
      return true;
    }

    bool unstash_block(uint64_t block_index){
      if (stash_block_ids.find(block_index) == stash_block_ids.end()){
        std::cerr << "block_storage: Error unstashing block with index= " << block_index << " No backing stash block" << std::endl; 
        return false;
      }
      std::string block_UUID = stash_block_ids[block_index];
      std::string block_temp_path = stash_directory + "/" + block_UUID;
      // remove file
      if (remove(block_temp_path.c_str()) == -1){
        return false;
      }
      // remove block_index from stash_block_ids
      stash_block_ids.erase(block_index);
      return true;
    }

    std::string commit_stash_block(uint64_t block_index){
      if (stash_block_ids.find(block_index) == stash_block_ids.end()){
        std::cerr << "block_storage: Error - block with index " << block_index << " has no backing stash file" << std::endl;
        exit(-1);
      }
      std::string block_stash_path = stash_directory + "/" + stash_block_ids[block_index];
      int block_fd = ::open(block_stash_path.c_str(), O_RDONLY);
      if (block_fd == -1){
        std::cerr << "bock_storage: Error opening stash file - " << strerror(errno) << std::endl;
        exit(-1);
      }
      void* temp_buffer = mmap(nullptr, block_granularity, PROT_READ, MAP_PRIVATE, block_fd, 0);
      if (temp_buffer == MAP_FAILED){
        std::cerr << "block_storage: Error mmapping temp buffer for stash block - " << strerror(errno) << std::endl;
        exit(-1);
      }
      std::string block_hash = utility::compute_hash((char*) temp_buffer, block_granularity);
      if (close(block_fd) == -1){
        std::cerr << "block_storage: Error closing file " << strerror(errno) << std::endl;
        exit(-1);
      }
      // Get block subdirectory
      std::string subdirectory_name;
      bool is_stash = is_multi_tiered();
      subdirectory_name = get_blocks_subdirectory(block_hash, is_stash);
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
            stash_block_ids.erase(block_index);
            if (is_multi_tiered()){
              // storing to only base_directory since stash has already been stored
              block_hash = store_block(temp_buffer, true, block_index, false, block_hash);
              if (block_hash.empty()){
                std::cerr << "block_storage: Error committing stash block with index: " << block_index << " to base path" << std::endl;
                return "";
              }
              // store block must have two versions ?? STOPPED HERE
            }
            return block_hash;
          }
          else{
            std::cerr << "block_storage: Error renaming file " << strerror(errno) << std::endl;
            std::cerr << "Stash file name = " << stash_filename << std::endl;
            return "";
          }
        }
        else{
          block_hash = store_block(temp_buffer, true, block_index, false, block_hash);
          if (block_hash.empty()){
            std::cerr << "block_storage: Error committing stash block with index: " << block_index << " to base path" << std::endl;
            return "";
          }
          stash_block_ids.erase(block_index);
          return block_hash;
        }
      }
      else{
        int remove_status = remove(stash_filename.c_str());
        if (remove_status != 0){
          std::cerr << "block_storage: Error removing stash file" << std::endl;
          return "";
        }
        block_hash = store_block(temp_buffer, true, block_index, false, block_hash);
        if (block_hash.empty()){
          std::cerr << "block_storage: Error committing stash block with index: " << block_index << " to base path" << std::endl;
          return "";
        }
        stash_block_ids.erase(block_index);
        return block_hash;
      }
    }

    std::string get_block_full_path(uint64_t block_index, std::string block_hash){
      std::string base_subdir = get_blocks_subdirectory(block_hash, false);
      if (is_multi_tiered()){
        std::string stash_subdir =  get_blocks_subdirectory(block_hash, true);
        if (stash_committed_block_ids.find(block_index) == stash_committed_block_ids.end()){
          std::string stash_block_path = stash_subdir + "/" + block_hash;
          std::string base_block_path = base_subdir + "/" + block_hash;
          if (!copy_to_stash(base_block_path, stash_block_path)){
            std::cerr << "block_storage: Error copying block with index: " << block_index << " and ID: " << block_hash << " From base directory to stash directory" << std::endl;
            exit(-1);
          } // TODO: Copy only the file not all dir.
          stash_committed_block_ids.insert(std::pair<uint64_t,std::string>(block_index, block_hash));
        }
        return stash_subdir;
      }
      else{
        return base_subdir;
      } 
    }

    // char* get_block_hash(int fd);
    size_t get_block_granularity(){
      return block_granularity;
    }
    
    std::string get_block_stash_path(size_t block_index){
      std::string block_stash_path = "";
      if (stash_block_ids.find(block_index) != stash_block_ids.end()){
        block_stash_path = stash_directory + "/" + stash_block_ids[block_index];
      }
      return block_stash_path;
    }

    std::string get_blocks_path(){
      return base_directory;
    }

    bool copy_to_stash(std::string base_block, std::string stash_block){
      if(!utility::file_exists(stash_block.c_str())){
        return utility::copy_file(base_block.c_str(), stash_block.c_str(), false);
      }
      return true;
    }

    static size_t get_version_block_granularity(std::string blocks_path){
      std::string granularity_string;
      std::string granularity_file_name = blocks_path + "/_granularity";
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
      return std::stol(granularity_string);
    }

  private:
    void create(std::string base_directory_path, std::string stash_directory_path, size_t block_granularity_arg){
      // std::cout << "stash directory path at create() " << stash_directory_path << std::endl;
      stash_directory = stash_directory_path;
      if (!stash_directory.empty()){
        // Create stash directory
        if (!utility::directory_exists(stash_directory_path.c_str())){
          if (!utility::create_directory(stash_directory_path.c_str())){
            std::cerr << "Error: Failed to create stash directory" << std::endl;
            exit(-1);
          }
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
      /* else{
        std::cerr << "block_storage: Error - Blocks directory already exists" << std::endl;
        exit(-1);
      } */
    }

    void open(std::string base_directory_path, std::string stash_directory_path){
      stash_directory = stash_directory_path;
      if (!stash_directory.empty()){
        // Create stash directory
        if (!utility::directory_exists(stash_directory_path.c_str())){
          if (!utility::create_directory(stash_directory_path.c_str())){
            std::cerr << "Error: Failed to create stash directory" << std::endl;
            exit(-1);
          }
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

    std::string get_blocks_subdirectory(std::string block_hash, bool on_stash){
      std::string base_path = on_stash ? stash_directory : base_directory;
      std::string block_hash_prefix = "0x" + block_hash.substr(0,hash_prefix_length);
      size_t block_prefix_index = std::stoul(block_hash_prefix, nullptr, 16);
      size_t subdir_index = block_prefix_index % num_subdirs;
      std::string subdir_name = base_path + "/" + std::to_string(subdir_index);
      if (!utility::directory_exists(subdir_name.c_str())){
        if (!utility::create_directory(subdir_name.c_str())){
            std::cerr << "Error: Failed to create blocks subdirectory" << std::endl;
            exit(-1);
        }
      }

      return subdir_name;
    }

    std::string store_block(void* buffer, bool write_to_file, uint64_t block_index, bool on_stash, std::string pre_computed_hash){
      // std::cout << "BLOCK FD: " << block_fd << " Process ID: " << getpid() << std::endl;

      std::string block_hash = pre_computed_hash;
      if (block_hash.empty()){
        block_hash = utility::compute_hash((char*) buffer, block_granularity);
      }

      std::string subdirectory_name = get_blocks_subdirectory(block_hash, on_stash);

      std::string temporary_file_name_template = std::to_string(block_index) + "_temp_XXXXXX";
      char* name_template = (char*) temporary_file_name_template.c_str();
      std::pair<int, std::string> temp_file_fd_name = create_temporary_unique_block(subdirectory_name, name_template, block_index, on_stash);
      int block_fd = temp_file_fd_name.first;
      // std::cout << "block_storage: store_block() base_directory = " << base_directory << std::endl;
      // std::cout << "block_storage: store_block() std::string(base_directory) returns  " << std::string(base_directory) << std::endl;

      std::string final_filename = subdirectory_name + "/" + block_hash;
      std::string temporary_filename = temp_file_fd_name.second;

      if (!utility::file_exists(final_filename.c_str())){
        // Write
        if (write_to_file){
          #ifdef USE_COMPRESSION
          // std::cout << "USING COMPRESSION" << std::endl;
          std::pair<void*,size_t> compressed_buffer_and_size = utility::compress(buffer, block_granularity);
          void* const write_buffer = compressed_buffer_and_size.first;
          size_t compressed_block_size = compressed_buffer_and_size.second;
          /* std::cout << "compressed_block_size: " << compressed_block_size << std::endl;
          std::cout << "block_granularity: " << block_granularity << std::endl;*/
          int trunc_status = ftruncate(block_fd, compressed_block_size);
          if (trunc_status == -1){
            std::cerr << "Block Storage: Error sizing temporary file to compressed size" << std::endl;
            exit(-1);
          }
          size_t written = pwrite(block_fd ,write_buffer, compressed_block_size, 0);
          if (written == -1){
            std::cerr << "block_storage: Error writing to file - " << strerror(errno) << std::endl;
            // store_block_mutex->unlock();
            return "";
          }
          free(write_buffer);
          #else
          size_t written = pwrite(block_fd ,buffer, block_granularity, 0);
          if (written == -1){
            std::cerr << "block_storage: Error writing to file - " << strerror(errno) << std::endl;
            // store_block_mutex->unlock();
            return "";
          }
          #endif
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
              return "";
            }
            if (::close(block_fd) == -1){
              std::cerr << "virtual_memory_manager: Error closing file descriptor for block: " << block_index << " - " << strerror(errno) << std::endl;
              exit(-1);
            }
            return block_hash;
          }
          else{
            std::cerr << "block_storage: Error renaming file " << strerror(errno) << std::endl;
            std::cerr << "Temporary file name = " << temporary_filename << std::endl;
            std::cerr << "Final file name = " << final_filename << std::endl;
          }
          if (::close(block_fd) == -1){
            std::cerr << "virtual_memory_manager: Error closing file descriptor for block: " << block_index << " - " << strerror(errno) << std::endl;
            exit(-1);
          }
          return "";
        }
      }
      else{
        int remove_status = remove(temporary_filename.c_str());
        if (remove_status != 0){
          std::cerr << "block_storage: Error removing temporary file" << std::endl;
          if (::close(block_fd) == -1){
            std::cerr << "virtual_memory_manager: Error closing file descriptor for block: " << block_index << " - " << strerror(errno) << std::endl;
            exit(-1);
          }
          return "";
        }
      }
      if (::close(block_fd) == -1){
        std::cerr << "virtual_memory_manager: Error closing file descriptor for block: " << block_index << " - " << strerror(errno) << std::endl;
        exit(-1);
      }
      return block_hash;
    }

    bool is_multi_tiered(){
      // std::cout << "BASE_DIRECTORY: " << base_directory << std::endl;
      // std::cout << "STASH DIRECTORY: " << stash_directory << std::endl;
      size_t base_suffix_start = base_directory.find_last_of("/");
      size_t stash_suffix_start = stash_directory.find_last_of("/");
      std::string base_prefix = base_directory.substr(0, base_suffix_start);
      std::string stash_prefix = stash_directory.substr(0, stash_suffix_start);
      // std::cout << "BASE_PREFIX: " << base_prefix << std::endl;
      // std::cout << "STASH_PREFIX: " << stash_prefix << std::endl;
      return (base_prefix.compare(stash_prefix) != 0);
    }

    std::pair<int,std::string> create_temporary_unique_block(std::string prefix, char* name_template, uint64_t block_index, bool on_stash){
      // std::lock_guard<std::mutex> store_lock(store_block_mutex);
      // std::string subdirectory_name = get_blocks_subdirectory(block_index, on_stash);
      std::string temporary_file_name = prefix + "/" + std::string(name_template);
      char* temporary_file_name_template = new char[temporary_file_name.length() + 1];
      temporary_file_name_template = (char*) memcpy((void*) temporary_file_name_template, (void*) temporary_file_name.c_str(), temporary_file_name.length() + 1);
      // std::cout << "block_storage: temporary_file_name_template =" << temporary_file_name_template << std::endl;
      int fd = mkstemp(temporary_file_name_template);
      if (fd == -1){
        std::cerr << "block_storage: Error creating temporary file" << strerror(errno) << std::endl;
        exit(-1);
      }
      // unlink(temporary_file_name_template);
      // std::cout << "block_storage: block_granularity = " << block_granularity << std::endl;
      #ifndef USE_COMPRESSION
      // std::cout << "NOT USING COMPRESSION" << std::endl;
      int trunc_status = ftruncate(fd, block_granularity);
      if (trunc_status == -1){
        std::cerr << "Block Storage: Error sizing temporary file" << std::endl;
        exit(-1);
      }
      #endif
      // std::cout << "Adding file with fd= " << fd << std::endl;
      /* if (block_fd_temp_name.find(fd) == block_fd_temp_name.end()){
        block_fd_temp_name.insert(std::pair<int, std::string>(fd, std::string(temporary_file_name_template)));
      }
      else{
        block_fd_temp_name[fd] = temporary_file_name_template;
      } */
      std::pair<int, std::string> fd_name (fd,std::string(temporary_file_name_template));
      delete temporary_file_name_template;
      return fd_name;
    }

    std::string base_directory;
    std::string stash_directory;
    size_t block_granularity;
    // std::map<int, std::string> block_fd_hash;
    // std::map<int, std::string> block_fd_temp_name;
    std::map<uint64_t, std::string> stash_block_ids;
    std::map<uint64_t, std::string> stash_committed_block_ids;
    bool block_exists(const char* hash);
    // std::mutex * store_block_mutex;
    // bip::named_mutex *store_block_mutex; // (bip::open_or_create, "store_block_mutex");
    std::mutex create_block_directory_mutex;
    size_t num_subdirs = 1024;
    size_t hash_prefix_length = 6;
    // std::atomic<size_t> num_files = 0;
};

