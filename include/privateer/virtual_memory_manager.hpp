#pragma once

#include <sys/mman.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <fcntl.h>
#include <iostream>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <list>
#include <set>
#include <sys/time.h>
#include <stdio.h>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <thread>
#include <mutex>
#include <omp.h>

#include "block_storage.hpp"

#ifdef USE_COMPRESSION
#include "utility/compression.hpp"
#endif

class virtual_memory_manager {
  public:
    virtual_memory_manager(void* start_address, size_t region_max_capacity, size_t block_size,
                                                    std::string version_metadata_path, std::string blocks_path, std::string stash_path, bool allow_overwrite){
      // Verify system page alignment
      size_t pagesize = sysconf(_SC_PAGE_SIZE);
      if ( ((uint64_t) start_address) % pagesize != 0){
        std::cerr << "Error: start_address is not system-page aligned" << std::endl;
        exit(-1);
      }

      /* if (region_max_capacity % num_blocks == 0){
        m_block_size = region_max_capacity / num_blocks;
      }
      else{
        std::cerr << "PRIVATEER_NUM_BLOCKS is set, but region capacity is not divisible by it "<< std::endl;
        exit(-1);
      } */
        
      // Verify multiple of system's page size
      /* if (m_block_size % pagesize != 0){
        std::cerr << "Error: block_size must be multiple of system page size (" << pagesize << ")" << std::endl;
        exit(-1);
      } */
      // Verity region capacity is multiple of block size
      m_block_size = block_size;
      if (region_max_capacity % m_block_size != 0 && region_max_capacity != 0){
        // Round capacity to nearest larger multiple of block size
        region_max_capacity = ((region_max_capacity / m_block_size) + 1) * m_block_size;

        /* std::cerr << "region_max_capacity: " <<  region_max_capacity << std::endl;
        std::cerr << "m_block_size: " << m_block_size << std::endl;
        if (region_max_capacity > m_block_size){
          std::cerr << "Virtual Memory Manager: Error - region size must be a non-zero multiple of block size" << std::endl;
          exit(-1);
        }
        else{
          // std::cout << "WARNING: region capacity less than block size, setting block size to region capacity" << std::endl;
          m_block_size = region_max_capacity;
        } */
      }
      size_t max_mem_size_blocks = utility::get_environment_variable("PRIVATEER_MAX_MEM_BLOCKS");
      if ( std::isnan((double)max_mem_size_blocks) || max_mem_size_blocks == 0){
        max_mem_size_blocks = MAX_MEM_DEFAULT_BLOCKS;
      }
      
      create_version_metadata(version_metadata_path.c_str(), blocks_path.c_str(), region_max_capacity, allow_overwrite);
      
      // m_block_size = block_size;
      m_region_max_capacity = region_max_capacity;
      m_max_mem_size = max_mem_size_blocks * m_block_size;
      m_version_metadata_path = version_metadata_path;

      m_block_storage = new block_storage(blocks_path, stash_path, m_block_size);

      
      // mmap region with full size
      int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE;
      if (start_address != nullptr)
      {
        flags |= MAP_FIXED;
      }
      m_region_start_address = mmap(start_address, m_region_max_capacity, PROT_NONE, flags, -1, 0);
      if (m_region_start_address == MAP_FAILED){
        std::cerr << "virtual_memory_manager: Error mmap-ing region starting address -  " << strerror(errno)<< std::endl;
        exit(-1);
      }

      size_t num_blocks = m_region_max_capacity / m_block_size;
      // std::cout << "num_blocks: " << num_blocks << std::endl;
      blocks_ids = new std::string[num_blocks];
      // blocks_locks = new std::mutex[num_blocks];
      // std::cout << "DEBUG: before init blocks_ids" << std::endl;
      for (size_t i = 0 ; i < num_blocks ; i++){
        blocks_ids[i] = EMPTY_BLOCK_HASH;
      }
      // std::cout << "DEBUG: after init blocks_ids" << std::endl;
      
      struct stat st_dev_null;
      if (fstat(0,&st_dev_null) != 0){
        // std::cout << "Opening /dev/null" << std::endl;
        int dev_null_fd = ::open("/dev/null",O_RDWR);
        // std::cout << "/dev/null FD: " << dev_null_fd << std::endl;
      }

      m_read_only = false;
    }

    virtual_memory_manager(void* addr, std::string version_metadata_path, std::string stash_path, bool read_only){

      m_version_metadata_path = version_metadata_path;
      // Read blocks path
      std::string blocks_path_file_name = std::string(m_version_metadata_path) + "/_blocks_path";
      std::ifstream blocks_path_file;
      std::string blocks_dir_path;
      
      blocks_path_file.open(blocks_path_file_name);
      if (!blocks_path_file.is_open()){
        std::cerr << "Error opening blocks file path at: " << blocks_path_file_name << std::endl;
      }
      if (!std::getline(blocks_path_file, blocks_dir_path)){
        std::cerr << "Error reading blocks path file" << std::endl;
      } 
      m_block_storage = new block_storage(blocks_dir_path, stash_path);
      m_block_size = m_block_storage->get_block_granularity();
      std::string metadata_file_name = std::string(m_version_metadata_path) + "/_metadata";
      int flags = read_only? O_RDONLY: O_RDWR;
      int metadata_fd = ::open(metadata_file_name.c_str(), flags, (mode_t) 0666);
      assert(metadata_fd != -1);
      struct stat st;
      fstat(metadata_fd, &st);
      size_t metadata_size = st.st_size;
      
      // Start: Read capacity file
      m_region_max_capacity = version_capacity(version_metadata_path);
      
      size_t num_blocks = m_region_max_capacity / m_block_size;
      int mmap_flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE;
      if (addr != nullptr)
      {
        mmap_flags |= MAP_FIXED;
      }
      
      m_region_start_address = mmap(addr, m_region_max_capacity, PROT_NONE, mmap_flags, -1, 0);
      if (m_region_start_address == MAP_FAILED){
        std::cerr << "virtual_memory_manager: mmap error - " << strerror(errno)<< std::endl;
        exit(-1);
      }
      
      
      blocks_ids = new std::string[num_blocks];
      char* metadata_content = new char[metadata_size];
      size_t read = ::pread(metadata_fd, (void*) metadata_content, metadata_size, 0);
      if (read == -1){
        std::cerr << "virtual_memory_manager: Error reading metadata - " << strerror(errno) << std::endl;
        exit(-1);
      }
      
      std::string all_hashes(metadata_content, metadata_size);
      
      uint64_t offset = 0;
      for (size_t i = 0; i < metadata_size; i += HASH_SIZE){
        std::string block_hash(all_hashes, i, HASH_SIZE);
        blocks_ids[i / HASH_SIZE] = block_hash;
      }
      
      size_t num_occupied_blocks = metadata_size / HASH_SIZE;
      for (size_t i = num_occupied_blocks; i < num_blocks; i++){
        blocks_ids[i] = EMPTY_BLOCK_HASH;
      }

      
      delete [] metadata_content;
      

      size_t max_mem_size_blocks = utility::get_environment_variable("PRIVATEER_MAX_MEM_BLOCKS");
      if ( std::isnan((double)max_mem_size_blocks) || max_mem_size_blocks == 0){
        max_mem_size_blocks = MAX_MEM_DEFAULT_BLOCKS;
      }
      m_max_mem_size = max_mem_size_blocks * m_block_size;

      // In some cases /dev/null file descriptorr was affected, temporary solution is check and re-open
      struct stat st_dev_null;
      if (fstat(0,&st_dev_null) != 0){
        int dev_null_fd = ::open("/dev/null",O_RDWR);
      }
    }
    
    ~virtual_memory_manager(){
      if (close() !=0){
        std::cerr << "virtual_memory_manager: Error, image not closed appropriately" << std::endl;
        exit(-1);
      }
    }

    void msync(){
      // 1) Write dirty_lru
      std::vector<uint64_t> dirty_lru_vector(dirty_lru.begin(), dirty_lru.end());
      #pragma omp parallel for
      for (auto dirty_lru_iterator = dirty_lru_vector.begin(); dirty_lru_iterator != dirty_lru_vector.end(); ++dirty_lru_iterator){
        block_storage block_storage_local(*m_block_storage);
        void* block_address = (void*) *dirty_lru_iterator;
        // if (stash_set.find((uint64_t) block_address) == stash_set.end()){
          uint64_t block_index = ((uint64_t) block_address - (uint64_t) m_region_start_address) / m_block_size;
          bool write_block_fd = true;
          std::string block_hash = block_storage_local.store_block(block_address, write_block_fd, block_index);
          if (block_hash.empty()){
            std::cerr << "virtual_memory_manager: Error storing block with index " << block_index << std::endl;
            exit(-1);
          }
          
          blocks_ids[block_index] = block_hash;// std::string(block_storage_local.get_block_hash(block_fd));
          // Change mprotect to read_only
          int mprotect_stat = mprotect(block_address, m_block_size, PROT_READ);
          if (mprotect_stat == -1){
            std::cerr << "virtual_memory_manager: mprotect error for block with address: " << (uint64_t) block_address << " " << strerror(errno) << std::endl;
            exit(-1);
          }
          #pragma omp critial
          {
            clean_lru.push_front((uint64_t)block_address);
          }
        // }
      }
      dirty_lru.clear();
      
      // 2) Commit stashed blocks
      std::vector<uint64_t> stash_vector(stash_set.begin(), stash_set.end());
      #pragma omp parallel for
      for (auto stash_iterator = stash_vector.begin(); stash_iterator != stash_vector.end(); ++stash_iterator){
        block_storage block_storage_local(*m_block_storage);
        void* block_address = (void*) *stash_iterator;
        uint64_t block_index = ((uint64_t) block_address - (uint64_t) m_region_start_address) / m_block_size;
        #pragma omp critical
        {
          std::string block_hash = /* block_storage_local.*/ m_block_storage->commit_stash_block(block_index);
          if (block_hash.empty()){
            std::cerr << "virtual_memory_manager: Error committing stash block with address: " << (uint64_t) block_address << std::endl;
            exit(-1);
          }
          blocks_ids[block_index] = block_hash;
        }
      }
      stash_set.clear();
      update_metadata();
      struct stat st_dev_null;
      if (fstat(0,&st_dev_null) != 0){
        int dev_null_fd = ::open("/dev/null",O_RDWR);
      }
    }

    void handler(int sig, siginfo_t *si, void *ctx_void_ptr){
      // const std::lock_guard<std::mutex> lock(sig_handler_mutex);
      // Get and assert faulting address
      uint64_t fault_address = (uint64_t) si->si_addr;
      uint64_t start_address = (uint64_t) m_region_start_address;
      uint64_t block_index = (fault_address - start_address) / m_block_size;
      uint64_t block_address = start_address + block_index * m_block_size;
      // std::cout << "thread: " << omp_get_thread_num() << " Faulted on block: " << (block_index % num_locks) << std::endl;
      // const std::lock_guard<std::mutex> lock(blocks_locks[block_index]); // lock(blocks_locks[block_index % num_locks]);
      // std::cout << "thread: " << omp_get_thread_num() << " grabbed lock number: " << (block_index % num_locks) << std::endl;
      /* if (fault_address < (uint64_t) start_address || fault_address >= (uint64_t) start_address + m_region_max_capacity){
        std::cerr << "Error: Faulting address out of range" << std::endl;
        std::cerr << "Faulting Address: " << (uint64_t) fault_address << std::endl;
        std::cerr << "Start:            " << (uint64_t) start_address << std::endl;
        std::cerr << "End:              " << (uint64_t) start_address + m_region_max_capacity << std::endl;
        exit(-1);
      } */
      // Handle block fault
      ucontext_t *ctx = (ucontext_t *) ctx_void_ptr;
      bool is_write_fault = ctx->uc_mcontext.gregs[REG_ERR] & 0x2;
      
      
      if (present_blocks.find((uint64_t) block_address) != present_blocks.end()){ // Block is present in-memory (just change prot and LRU if needed)
        
        if (is_write_fault){
          // Move from clean_lru to dirty_lru
          clean_lru.remove((uint64_t) block_address);
          dirty_lru.push_front((uint64_t) block_address);
          if (stash_set.find(block_address) != stash_set.end()){
            // std::cout << "STASHED TO CLEAN TO DIRTY" << std::endl;
            if (!m_block_storage->unstash_block(block_index)){
              std::cerr << "virtual_memory_manager: Error unstashing block with index= " << block_index << std::endl;
              exit(-1);
            }
            stash_set.erase(block_address);
          }
        }
        int mprotect_stat = mprotect((void*) block_address, m_block_size, PROT_READ | PROT_WRITE);
        if (mprotect_stat == -1){
          std::cerr << "virtual_memory_manager: mprotect error for block with address: " << (uint64_t) block_address << " " << strerror(errno) << std::endl;
          exit(-1);
        }
      }
      else{ // block is not present in-memory
        
        evict_if_needed();
        
        int prot = is_write_fault ? PROT_WRITE : PROT_READ;

        // Check if backing block exists
        int backing_block_fd = -1;
        std::string backing_block_path = "";
        std::string stash_backing_block_path = m_block_storage->get_block_stash_path(block_index); 
        std::string blocks_path = m_block_storage->get_blocks_path();
        // std::cout << "block_index = " << block_index << std::endl;
        if (!stash_backing_block_path.empty()){
          // std::cout << "Getting block: " << block_index << " from stash " << stash_backing_block_path << std::endl;
          backing_block_path = stash_backing_block_path;
        }
        else if(blocks_ids[block_index].compare(EMPTY_BLOCK_HASH) != 0){
          // std::cout << "Getting block: " << block_index << " from blocks " << blocks_ids[block_index] << std::endl;
          backing_block_path = m_block_storage->get_block_full_path(block_index, blocks_ids[block_index]) + "/" + blocks_ids[block_index];
        }
        
        if (!backing_block_path.empty()){ // Backing block exists
          #ifndef __linux__
          // shm_open
          boost::uuids::uuid uuid = boost::uuids::random_generator()();
          const std::string block_name = boost::lexical_cast<std::string>(uuid);
          int shm_fd = shm_open(block_name.c_str(), O_CREAT | O_RDWR, S_IWUSR);
          // std::cout << "shm_fd: " << shm_fd << std::endl;
          if (shm_fd == -1){
            std::cerr << "Error shm_open: " << strerror(errno) << std::endl;
          }
          int trunc_status = ftruncate(shm_fd, m_block_size);
          if (trunc_status == -1){
            std::cerr << "Error ftruncate: " << strerror(errno) << std::endl;
          }
          // shm_unlink
          if (shm_unlink(block_name.c_str()) == -1){
            std::cerr << "virtual_memory_manager: Error shm_unlink: " << strerror(errno) << std::endl;
            exit(-1);
          }
          // mmap temporary location
          void* temp_buffer =  mmap(nullptr, m_block_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
          #else
          
          void* temp_buffer =  mmap(nullptr, m_block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
          #endif
          if (temp_buffer == MAP_FAILED){
            std::cerr << "Error mmap temp: " << strerror(errno) << std::endl;
            exit(-1);
          }
          
          // read block content into temporary buffer
          backing_block_fd = open(backing_block_path.c_str(), O_RDONLY);
          if (backing_block_fd == -1){
            std::cerr << "virtual_memory_manager: Error opening backing block: " << backing_block_path  << " for address: " << block_address << " - " << strerror(errno) << std::endl;
            exit(-1);
          }
          #ifdef USE_COMPRESSION
          // std::cout << "USING COMPRESSION DECOMPRESSING" << std::endl;
          size_t compressed_block_size = utility::get_file_size(backing_block_path.c_str());
          void* const read_buffer = malloc(compressed_block_size);
          if (pread(backing_block_fd, read_buffer, compressed_block_size, 0) == -1){
            std::cerr << "virtual_memory_manager: Error reading backing block: " << backing_block_path << " for address: " << " - " << strerror(errno) << block_address << std::endl;
            exit(-1);
          }
          size_t decompressed_size = utility::decompress(read_buffer, temp_buffer, compressed_block_size);
          free(read_buffer);
          #else
          
          if (pread(backing_block_fd, temp_buffer, m_block_size, 0) == -1){
            std::cerr << "virtual_memory_manager: Error reading backing block: " << backing_block_path << " for address: " << " - " << strerror(errno) << block_address << std::endl;
            exit(-1);
          }
          #endif
          
          if (::close(backing_block_fd) == -1){
            std::cerr << "virtual_memory_manager: Error closing backing block: " << backing_block_path << " - " << strerror(errno) << std::endl;
            exit(-1);
          }

          #ifndef __linux__
          // mmap original block
          void *mmap_block_address = mmap((void*) block_address, m_block_size, prot, MAP_PRIVATE | MAP_FIXED, shm_fd,0);
          #else
          if (mprotect(temp_buffer, m_block_size, prot) != 0){
            std::cerr << "Error updating permissions on temporary buffer for block: " << block_address << std::endl;
            exit(-1);
          }
          void *mmap_block_address = mremap(temp_buffer, m_block_size, m_block_size, MREMAP_FIXED | MREMAP_MAYMOVE, block_address);
          #endif
          if (mmap_block_address == MAP_FAILED){
            std::cerr << "virtual_memory_manager: Error remapping address: " << block_address << std::endl;
            exit(-1);
          }

          #ifndef __linux__
          // unmap temp buffer
          int munmap_status = munmap(temp_buffer, m_block_size);
          if (munmap_status == -1){
            std::cerr << "virtual_memory_manager: Error unmapping temp buffer: " << (uint64_t) temp_buffer << " for faulting block address: " << block_address << std::endl;
            exit(-1);
          }
          
          // close shm_fd
          if (::close(shm_fd) == -1){
            std::cerr << "virtual_memory_manager: Error closing shm_fd: " << strerror(errno) << std::endl;
            exit(-1);
          }
          #endif
          // unstash block
          if ((!stash_backing_block_path.empty()) && is_write_fault){
            // std::cout << "STASHED TO DIRTY: " << block_index << std::endl;
            if(!m_block_storage->unstash_block(block_index)){
              std::cerr << "virtual_memory_manager: Error un-stashing block with index= " << block_index << std::endl;
              exit(-1);
            }
            stash_set.erase(block_address);
          }
        }
        else{ // No backing block yet, just change mprotect
          if (mprotect((void*) block_address, m_block_size, prot) == -1){
            std::cerr << "virtual_memory_manager: Error changing PROT for block: " << block_address << " - " << strerror(errno) << std::endl;
            exit(-1);
          }
        }
        // Update LRUs
        if (is_write_fault){
          dirty_lru.push_front(block_address);
        }
        else{
          clean_lru.push_front(block_address);
        }
        present_blocks.insert((uint64_t)block_address);
      }
      // std::cout << "DONE HANDLER" << std::endl;
    }

    void* get_region_start_address(){
      return m_region_start_address;
    }

    size_t static version_capacity(std::string version_path){
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

    size_t static version_block_size(std::string version_path){
      std::string blocks_path_file_name = std::string(version_path) + "/_blocks_path";
      std::ifstream blocks_path_file;
      std::string blocks_dir_path;
      
      blocks_path_file.open(blocks_path_file_name);
      if (!blocks_path_file.is_open()){
        std::cerr << "Error opening blocks file path at: " << blocks_path_file_name << std::endl;
        exit(-1);
      }
      if (!std::getline(blocks_path_file, blocks_dir_path)){
        std::cerr << "Error reading blocks path file" << std::endl;
        exit(-1);
      } 
      return block_storage::get_version_block_granularity(blocks_dir_path);
    }

    size_t current_region_capacity(){
      return m_region_max_capacity;
    }

    bool snapshot(const char* version_metadata_path){

      std::string snapshot_metadata_path = std::string(version_metadata_path) + "/_metadata";
      std::string m_temp_current_metadata_path = m_version_metadata_path;

      // Create new version metadata directory
      if(utility::directory_exists(version_metadata_path)){
        if (utility::file_exists(snapshot_metadata_path.c_str())){
          std::cerr << "Error: Version metadata directory already exists" << std::endl;
          return false;
        }
      }

      else if (!utility::create_directory(version_metadata_path)){
        std::cerr << "Error: Failed to create version metadata directory at " << version_metadata_path << " - " << strerror(errno) << std::endl;
        return false;
      }

      // temporarily change metadata file descriptor
      // int temp_metada_fd = metadata_fd;
      m_version_metadata_path = std::string(version_metadata_path);

      int metadata_fd = ::open(snapshot_metadata_path.c_str(), O_RDWR | O_CREAT, (mode_t) 0666);
      int close_status = ::close(metadata_fd);
      
      msync();
      m_version_metadata_path = m_temp_current_metadata_path;
      // metadata_fd = temp_metada_fd;

      // Create file to save blocks path
      std::string blocks_path_file_name = std::string(version_metadata_path) + "/_blocks_path";
      std::ofstream blocks_path_file;
      blocks_path_file.open(blocks_path_file_name);
      blocks_path_file << m_block_storage->get_blocks_path();
      blocks_path_file.close();

      // Create file to save max. capacity
      std::string capacity_path_file_name = std::string(version_metadata_path) + "/_capacity";
      std::ofstream capacity_path_file;
      capacity_path_file.open(capacity_path_file_name);
      capacity_path_file << m_region_max_capacity;
      capacity_path_file.close();

      return true;
    }

    size_t get_block_size(){
      return m_block_size;
    }

    int close(){
      //  << "ByeBye VMM" << std::endl;
      msync();
      std::set<uint64_t>::iterator it;
      for (it = present_blocks.begin(); it != present_blocks.end(); ++it) {
          void* address = (void*) *it;
          int status = munmap(address, m_block_size);
          if (status == -1){
            std::cerr << "virtual_memory_manager: Error unmapping region with address: " << *it << " - " << strerror(errno) << std::endl;
            return -1;
          }
      }
      delete [] blocks_ids;
      // delete [] blocks_locks;
      delete m_block_storage;
      m_region_start_address = nullptr;
      return 0;
    }

  private:
    void* m_region_start_address;
    size_t m_block_size;
    size_t m_region_max_capacity;
    size_t m_max_mem_size;
    std::string m_version_metadata_path;
    bool m_read_only;
    int metadata_fd;
    std::list<uint64_t> clean_lru;
    std::list<uint64_t> dirty_lru;
    std::set<uint64_t> stash_set;
    std::set<uint64_t> present_blocks;
    std::string *blocks_ids;
    
    const size_t MAX_MEM_DEFAULT_BLOCKS = 16384;
    const size_t HASH_SIZE = 64;
    const std::string EMPTY_BLOCK_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    block_storage *m_block_storage;

    // std::mutex* blocks_locks;
    // size_t num_locks = 2048;
    std::mutex sig_handler_mutex;

    void evict_if_needed(){
      void* to_evict;
      if ((present_blocks.size()*m_block_size) >= m_max_mem_size){
        // std::cout << "EVICTING" << std::endl;
        if (clean_lru.size() > 0){
          to_evict = (void*) clean_lru.back();
          // std::cout << "Evicting clean block: " << ((uint64_t) to_evict - (uint64_t) m_region_start_address) / m_block_size << std::endl;
          clean_lru.pop_back();
        }
        else{
          // std::cout << "I am failing, bye!" << std::endl;
          to_evict = (void*) dirty_lru.back();
          dirty_lru.pop_back();
          // std::cout << "Hello from the other side" << std::endl;
          uint64_t block_index = ((uint64_t) to_evict - (uint64_t) m_region_start_address) / m_block_size;
          // std::cout << "stashing block: " << block_index << std::endl;
          if (!m_block_storage->stash_block(to_evict, block_index)){
            std::cerr << "Virtual memory manager: Error stashing block with index: " << block_index << std::endl;
            exit(-1);
          }
          stash_set.insert((uint64_t) to_evict);
        }
        int protect_status = mprotect(to_evict, m_block_size, PROT_NONE);
        if (protect_status == -1){
          std::cerr << "virtual_memory_manager: Error evicting address: " << to_evict << std::endl;
          exit(-1);
        }
        present_blocks.erase((uint64_t) to_evict);
      }
    }

    void update_metadata(){
      // std::cout << "present_blocks.size(): " << present_blocks.size() << std::endl;
      if (present_blocks.size() == 0){
        return;
      }
      size_t max_address = *present_blocks.rbegin();
      size_t current_size = max_address - (uint64_t) m_region_start_address + m_block_size;
      size_t num_blocks = current_size / m_block_size; // m_region_max_capacity / m_block_size;
      // std::cout << "update_metadata() current_size: " << current_size << std::endl;
      // std::cout << "update_metadata() num_blocks:   " << num_blocks << std::endl;
      char* blocks_bytes = new char[num_blocks*HASH_SIZE];
      for (size_t i = 0 ; i < num_blocks ; i++){
        const char* block_hash_bytes = blocks_ids[i].c_str();
        /* if (blocks[i].compare(EMPTY_BLOCK_HASH) != 0){
          current_size = (i+1)*file_granularity;
        } */
        for (int j = 0; j < HASH_SIZE; j++){
          blocks_bytes[i*HASH_SIZE + j] = block_hash_bytes[j];
        }
      }

      std::string metadata_path = m_version_metadata_path + "/_metadata";
      // std::cout << "update metadata to path: " << metadata_path << std::endl;
      int metadata_fd = open(metadata_path.c_str(), O_RDWR);
      if (metadata_fd == -1){
        std::cerr << "virtual_memory_manager: Error opening metadata file " << strerror(errno) << std::endl;
        exit(-1);
      }
      const auto written = ::pwrite(metadata_fd ,(void*) blocks_bytes, num_blocks*HASH_SIZE, 0);
      if (written == -1){
        std::cerr << "Error, failed to update metadata and mappings: " << strerror(errno) << std::endl;
        exit(-1);
      }
      if (::close(metadata_fd == -1)){
        std::cerr << "Virtual Memory Manager: Error closing metadata file after update - " << strerror(errno) << std::endl;
        exit(-1);
      }
      delete [] blocks_bytes;
    }

    void create_version_metadata(const char* version_metadata_dir_path, const char* block_storage_dir_path, size_t version_capacity, bool allow_overwrite){
      std::string metadata_file_name = std::string(version_metadata_dir_path) + "/_metadata";
      std::string blocks_path_file_name = std::string(version_metadata_dir_path) + "/_blocks_path";
      std::string capacity_file_name = std::string(version_metadata_dir_path) + "/_capacity";

      // Create version directory
      if (utility::directory_exists(version_metadata_dir_path)){
        if (utility::file_exists(metadata_file_name.c_str()) || utility::file_exists(blocks_path_file_name.c_str()) || utility::file_exists(capacity_file_name.c_str())){
          if (allow_overwrite){
            if (!std::filesystem::remove(std::filesystem::path(metadata_file_name)) || !std::filesystem::remove(std::filesystem::path(blocks_path_file_name)) || !std::filesystem::remove(std::filesystem::path(capacity_file_name))){
              std::cerr << "Error removing existing metadata files" << std::endl;
              exit(-1);
            }
            if (!utility::create_directory(version_metadata_dir_path)){
              std::cerr << "Error: Failed to create version metadata directory at " << version_metadata_dir_path << " - " << strerror(errno) << std::endl;
              exit(-1);
            }
          }
          else{
            std::cerr << "Error: Version metadata already exists" << std::endl;
            exit(-1);
          }
        }
      }
      else if (!utility::create_directory(version_metadata_dir_path)){
        std::cerr << "Error: Failed to create version metadata directory at " << version_metadata_dir_path << " - " << strerror(errno) << std::endl;
        exit(-1);
      }
      // Create blocks metadata file
      metadata_fd = ::open(metadata_file_name.c_str(), O_RDWR | O_CREAT | O_EXCL, (mode_t) 0666);
      if (metadata_fd == -1){
        std::cerr << "Privateer: Error opening metadata file: " << metadata_file_name << " - " << strerror(errno) << std::endl;
        exit(-1);
      }
      // Create file to save blocks path
      std::ofstream blocks_path_file;
      blocks_path_file.open(blocks_path_file_name);
      blocks_path_file << block_storage_dir_path;
      blocks_path_file.close();

      // Create capacity file
      std::ofstream capacity_file;
      capacity_file.open(capacity_file_name);
      capacity_file << version_capacity;
      capacity_file.close();
    }
};
