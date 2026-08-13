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

#ifdef USERFAULTFD
#define _GNU_SOURCE
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

#include <queue>
#include <chrono>

#include "utility/fault_event.hpp"
#include "utility/event_queue.hpp"
#endif

#include "block_storage.hpp"

#ifdef USE_COMPRESSION
#include "utility/compression.hpp"
#endif
#include "spdlog/spdlog.h"

class virtual_memory_manager {
  public:
    virtual_memory_manager(void* start_address, size_t region_max_capacity, size_t block_size,
                           std::string version_metadata_path, std::string blocks_path, std::string stash_path, bool allow_overwrite){
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager() - start");
#ifdef USERFAULTFD
      // printf("Waiting on handler_mutex_global create Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
      const std::lock_guard<std::mutex> lock(handler_mutex_global);
      // printf("Aquired handler_mutex_global create Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
      // std::cout << "VMM CREATING\n";
#endif

      // Verify system page alignment
      size_t pagesize = sysconf(_SC_PAGE_SIZE);
      if ( ((uint64_t) start_address) % pagesize != 0){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Start_address is not system-page aligned");
        exit(-1);
      }

#ifdef USERFAULTFD
      // Set num handling threads
      num_handling_threads = utility::get_environment_variable("NUM_HANDLING_THREADS");
      if (std::isnan(num_handling_threads) || num_handling_threads == 0){
        num_handling_threads = NUM_HANDLING_THREADS_DEFAULT;
      }
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "num_handling_threads: {}", num_handling_threads);

      // Set num msync threads
      num_msync_threads = utility::get_environment_variable("NUM_MSYNC_THREADS");
      if (std::isnan(num_msync_threads) || num_msync_threads == 0){
        num_msync_threads = NUM_MSYNC_THREADS_DEFAULT;
      }
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "num_msync_threads: {}", num_msync_threads);
#endif

      /* if (region_max_capacity % num_blocks == 0){
         m_block_size = region_max_capacity / num_blocks;
         }
         else{
         SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: PRIVATEER_NUM_BLOCKS is set, but region capacity is not divisible by it");
         exit(-1);
         } */
        
      // Verify multiple of system's page size
      /* if (m_block_size % pagesize != 0){

         SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: block_size must be multiple of system page size ({})", pagesize);
         exit(-1);
         } */
      // Verity region capacity is multiple of block size

      m_block_size = block_size;
      if (region_max_capacity % m_block_size != 0 && region_max_capacity != 0){
        // Round capacity to nearest larger multiple of block size
        region_max_capacity = ((region_max_capacity / m_block_size) + 1) * m_block_size;
        /*
          SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: region_max_capacity = {}", region_max_capacity);
          SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: m_block_size = {}", m_block_size);
          if (region_max_capacity > m_block_size){
          SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: region size must be a non-zero multiple of block size");
          exit(-1);
          }
          else{
          // std::cout << "WARNING: region capacity less than block size, setting block size to region capacity" << std::endl;
          m_block_size = region_max_capacity;
          } */
      }

      /*
      if (region_max_capacity < m_block_size){
        spdlog::warn("region capacity less than block size, setting block size to region capacity");
        spdlog::warn("{} < {}", region_max_capacity, m_block_size);
        m_block_size = region_max_capacity;
      } */
      // std::cout << "m_block_size after check: " << m_block_size << std::endl;

      size_t max_mem_size_blocks = utility::get_environment_variable("PRIVATEER_MAX_MEM_BLOCKS");
      if ( std::isnan((double)max_mem_size_blocks) || max_mem_size_blocks == 0){
        max_mem_size_blocks = MAX_MEM_DEFAULT_BLOCKS;
      }

#ifndef ENABLE_PAGE_EVICTION
      if (max_mem_size_blocks * m_block_size < m_region_max_capacity) {
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Page eviction not permitted");
      }
#endif

      create_version_metadata(version_metadata_path.c_str(), blocks_path.c_str(), region_max_capacity, allow_overwrite);
      
      // m_block_size = block_size;
      m_region_max_capacity = region_max_capacity;
      std::cout << "region max capacity: " << m_region_max_capacity << std::endl;
      m_max_mem_size = max_mem_size_blocks * m_block_size;
      m_version_metadata_path = version_metadata_path;

      m_block_storage = new block_storage(blocks_path, stash_path, m_block_size);

      
      // mmap region with full size
      int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE;
      if (start_address != nullptr)
      {
        flags |= MAP_FIXED;
      }

#ifdef SIGACTION
      m_region_start_address = mmap(start_address, m_region_max_capacity, PROT_NONE, flags, -1, 0);
#endif
#ifdef USERFAULTFD
      prot = PROT_READ | PROT_WRITE;
      m_region_start_address = mmap(start_address, m_region_max_capacity, prot, flags, -1, 0);
#endif

      if (m_region_start_address == MAP_FAILED){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: mmap-ing region starting address - {}", strerror(errno));
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

#ifdef SIGACTION
      struct stat st_dev_null;
      if (fstat(0,&st_dev_null) != 0){
        // std::cout << "Opening /dev/null" << std::endl;
        int dev_null_fd = ::open("/dev/null",O_RDWR);
        // std::cout << "/dev/null FD: " << dev_null_fd << std::endl;
      }
#endif

      m_read_only = false;

#ifdef USERFAULTFD
      uffd_active = true;

      /* pthread_mutex_init(&handler_mutex, NULL);

         if (pipe2(uffd_pipe, 0) < 0){
         SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Virtual Memory Manager: Error Userfaultfd pipe failed - {}", strerror(errno));
         exit(-1);
         } */
      sub_regions_mutex_list = std::vector<std::mutex>(num_handling_threads);
      events_queues = std::vector<utility::event_queue<utility::fault_event>>(num_handling_threads);
      for (int i = 0; i < num_handling_threads; i++){
        std::list<uint64_t> clean_lru_i;
        std::list<uint64_t> dirty_lru_i;
        std::set<uint64_t> stash_set_i;
        std::set<uint64_t> present_blocks_i;
        std::mutex sub_region_mutex;
        utility::event_queue<utility::fault_event> sub_region_event_queue;
        clean_lru.push_back(clean_lru_i);
        dirty_lru.push_back(dirty_lru_i);
        stash_set.push_back(stash_set_i);
        present_blocks.push_back(present_blocks_i);
        // sub_regions_mutex_list.push_back(sub_region_mutex);
      }

      // setup zero page and temp buffer
      char *tmp;
      if (posix_memalign((void**)&tmp, m_block_size, m_block_size)) {
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error posix_memalign - {}", strerror(errno));
      }
      zero_page = mmap((void *) tmp, m_block_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE, -1, 0);
      if (zero_page == MAP_FAILED){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error mmap zero page ", strerror(errno));
        exit(-1);
      }
      temp_buffer =  mmap(nullptr, m_block_size * num_handling_threads, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (temp_buffer == MAP_FAILED){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error mmap zero page ", strerror(errno));
        exit(-1);
      }
      // fault_events_queue = new utility::event_queue<utility::fault_event>(num_handling_threads);
      start_handler_thread();
      // printf("Releasing handler_mutex_global create Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
#endif
    }

    virtual_memory_manager(void* addr, std::string version_metadata_path, std::string stash_path, bool read_only){
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager() - start");
#ifdef USERFAULTFD
      const std::lock_guard<std::mutex> lock(handler_mutex_global);
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: Acquired virtual handler_mutex_global, open Thread ID: {}", (uint64_t) syscall(SYS_gettid));
      // std::cout << "VMM OPENING\n";

      num_handling_threads = utility::get_environment_variable("NUM_HANDLING_THREADS");
      if (std::isnan(num_handling_threads) || num_handling_threads == 0){
        num_handling_threads = NUM_HANDLING_THREADS_DEFAULT;
      }
      // std::cout << "num_handling_threads: " << num_handling_threads << std::endl;

      // Set num msync threads
      num_msync_threads = utility::get_environment_variable("NUM_MSYNC_THREADS");
      if (std::isnan(num_msync_threads) || num_msync_threads == 0){
        num_msync_threads = NUM_MSYNC_THREADS_DEFAULT;
      }

      // std::cout << "num_msync_threads: " << num_msync_threads << std::endl;

      // std::cout << "Opening :)" << std::endl;
      if (read_only){
        SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: Read-only!");
      }
#endif

      m_version_metadata_path = version_metadata_path;
      // Read blocks path
      std::string blocks_path_file_name = std::string(m_version_metadata_path) + "/_blocks_path";
      std::ifstream blocks_path_file;
      std::string blocks_dir_path;
      
      blocks_path_file.open(blocks_path_file_name);
      if (!blocks_path_file.is_open()){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error opening blocks file path at {}", blocks_path_file_name);
      }
      if (!std::getline(blocks_path_file, blocks_dir_path)){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error reading blocks path file");
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

#ifdef SIGACTION
      m_region_start_address = mmap(addr, m_region_max_capacity, PROT_NONE, mmap_flags, -1, 0);
#endif
#ifdef USERFAULTFD
      prot = read_only ? PROT_READ : (PROT_READ | PROT_WRITE);
      m_region_start_address = mmap(addr, m_region_max_capacity, prot, mmap_flags, -1, 0);
#endif

      if (m_region_start_address == MAP_FAILED){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: mmap error - {}", strerror(errno));
        exit(-1);
      }
      
      // std::cout << "Privateer Open 255" << std::endl;
      // std::cout << "num_blocks: " << num_blocks << std::endl;
      blocks_ids = new std::string[num_blocks];
      char* metadata_content = new char[metadata_size];
      size_t read = ::pread(metadata_fd, (void*) metadata_content, metadata_size, 0);
      if (read == -1){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error reading metadata - {}", strerror(errno));
        exit(-1);
      }
      // std::cout << "Privateer Open 264" << std::endl;
      std::string all_hashes(metadata_content, metadata_size);
      
      uint64_t offset = 0;
      // std::cout << "Privateer: Metadata size = " << metadata_size  << std::endl;
      for (size_t i = 0; i < metadata_size; i += HASH_SIZE){
        // std::cout << "Privateer: Initializing blocks and regions, iteration no. " << i << std::endl;
        // std::cout << "blocks_ids_index: " << (i / HASH_SIZE) << std::endl;
        std::string block_hash(all_hashes, i, HASH_SIZE);
        // std::cout << "before accessing array" << std::endl;
        blocks_ids[i / HASH_SIZE] = block_hash;
      }

      // std::cout << "Privateer Open 275" << std::endl;
      size_t num_occupied_blocks = metadata_size / HASH_SIZE;
      for (size_t i = num_occupied_blocks; i < num_blocks; i++){
        // std::cout << "blocks_ids_index Next: " << i << std::endl;
        blocks_ids[i] = EMPTY_BLOCK_HASH;
      }

      // blocks_locks = new std::mutex[num_blocks];
      
      delete [] metadata_content;
      // std::cout << "Privateer Open 285" << std::endl;
      

      size_t max_mem_size_blocks = utility::get_environment_variable("PRIVATEER_MAX_MEM_BLOCKS");
      if ( std::isnan((double)max_mem_size_blocks) || max_mem_size_blocks == 0){
        max_mem_size_blocks = MAX_MEM_DEFAULT_BLOCKS;
      }
      m_max_mem_size = max_mem_size_blocks * m_block_size;

#ifndef ENABLE_PAGE_EVICTION
      if (max_mem_size_blocks * m_block_size < m_region_max_capacity) {
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Page eviction not permitted");
      }
#endif

      // std::cout << "Privateer Open 292" << std::endl;
      // In some cases /dev/null file descriptor was affected, temporary solution is check and re-open
      struct stat st_dev_null;
      if (fstat(0,&st_dev_null) != 0){
        int dev_null_fd = ::open("/dev/null",O_RDWR);
      }
      m_read_only = read_only;

#ifdef USERFAULTFD
/* pthread_mutex_init(&handler_mutex, NULL);
   uffd_active = true;
   if (pipe2(uffd_pipe, 0) < 0){
   SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error Userfaultfd pipe failed - {}", strerror(errno));
   exit(-1);
   } // std::cout << "Privateer Open 304" << std::endl; */
      sub_regions_mutex_list = std::vector<std::mutex>(num_handling_threads);
      events_queues = std::vector<utility::event_queue<utility::fault_event>>(num_handling_threads);
      for (int i = 0; i < num_handling_threads; i++){
        std::list<uint64_t> clean_lru_i;
        std::list<uint64_t> dirty_lru_i;
        std::set<uint64_t> stash_set_i;
        std::set<uint64_t> present_blocks_i;
        std::mutex sub_region_mutex;
        clean_lru.push_back(clean_lru_i);
        dirty_lru.push_back(dirty_lru_i);
        stash_set.push_back(stash_set_i);
        present_blocks.push_back(present_blocks_i);
        // sub_regions_mutex_list.push_back(sub_region_mutex);
      }

      // setup zero page
      char *tmp;
      if (posix_memalign((void**)&tmp, m_block_size, m_block_size)) {
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error posix_memalign - {}", strerror(errno));
      }
      zero_page = mmap((void *) tmp, m_block_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE, -1, 0);
      if (zero_page == MAP_FAILED){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error mmap zero page - {}", strerror(errno));
        exit(-1);
      }

      temp_buffer =  mmap(nullptr, m_block_size * num_handling_threads, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (temp_buffer == MAP_FAILED){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error mmap zero page - {}", strerror(errno));
        exit(-1);
      }

      uffd_active = true;
      // fault_events_queue = new utility::event_queue<utility::fault_event>(num_handling_threads);
      start_handler_thread();
      // printf("Releasing handler_mutex_global open Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
#endif
    }
    
    ~virtual_memory_manager(){
      SPDLOG_LOGGER_TRACE(spdlog::default_logger(), "destructor, starting");
      if (close() !=0){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Image not closed appropriately");
        exit(-1);
      }

#ifdef USERFAULTFD
      if (munmap(zero_page, m_block_size) == -1){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error unmapping temporary buffer - {}", strerror(errno));
        exit(-1);
      }

      if (munmap(temp_buffer, m_block_size * num_handling_threads) == -1){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error unmapping temporary buffer - {}", strerror(errno));
        exit(-1);
      }
#endif
      SPDLOG_LOGGER_TRACE(spdlog::default_logger(), "destructor, done");
    }

#ifdef SIGACTION
    void msync(){
      // 1) Write dirty_lru
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: msync() - Msync Write Dirty LRU");
      std::vector<uint64_t> dirty_lru_vector(dirty_lru.begin(), dirty_lru.end());
#pragma omp parallel for
#endif

#ifdef USERFAULTFD
      void msync(){
        SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: msync() - start");
        for (int i = 0 ; i < num_handling_threads; i++){
          SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: msync({})", i);
          msync(i);
        }
        SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: msync() - done");
      }

      void msync(int sub_region_index){
        // 1) Write dirty_lru
        const std::lock_guard<std::mutex> lock(handler_mutex_global);
        SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: msync() - Msync Write Dirty LRU");
        // std::cout << "size of dirty LRU: "<< dirty_lru.size() << std::endl;
        std::vector<uint64_t> dirty_lru_vector(dirty_lru[sub_region_index].begin(), dirty_lru[sub_region_index].end());
        /* int num_threads = omp_get_num_threads() / num_handling_threads;
           omp_set_num_threads(num_threads); */
#pragma omp parallel for num_threads(num_msync_threads)
#endif

        for (auto dirty_lru_iterator = dirty_lru_vector.begin(); dirty_lru_iterator != dirty_lru_vector.end(); ++dirty_lru_iterator){
          block_storage block_storage_local(*m_block_storage);
          void* block_address = (void*) *dirty_lru_iterator;
          // if (stash_set.find((uint64_t) block_address) == stash_set.end()){
          uint64_t block_index = ((uint64_t) block_address - (uint64_t) m_region_start_address) / m_block_size;
          bool write_block_fd = true;
          std::string block_hash = block_storage_local.store_block(block_address, write_block_fd, block_index);
          if (block_hash.empty()){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error storing block with index {}", block_index);
            exit(-1);
          }

          blocks_ids[block_index] = block_hash;// std::string(block_storage_local.get_block_hash(block_fd));
#ifdef SIGACTION
          // Change mprotect to read_only
          int mprotect_stat = mprotect(block_address, m_block_size, PROT_READ);
          if (mprotect_stat == -1){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: mprotect error for block with address: {} - {}", (uint64_t) block_address, strerror(errno));
          }
#pragma omp critial
          {
            clean_lru.push_front((uint64_t)block_address);
          }
          // }
        }
        dirty_lru.clear();

        // 2) Commit stashed blocks
        SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: msync() - Msync Commit Stashed Blocks");
        std::vector<uint64_t> stash_vector(stash_set.begin(), stash_set.end());
#endif

#ifdef USERFAULTFD
#pragma omp critical
        {
          // std::cout << "wp-ing block\n";
          is_valid_uffd(m_uffd);
          //*
          struct uffdio_writeprotect uffdio_writeprotect;
          uffdio_writeprotect.range.start = (uint64_t) block_address;
          uffdio_writeprotect.range.len = (uint64_t) m_block_size;
          uffdio_writeprotect.mode = UFFDIO_WRITEPROTECT_MODE_WP; // UFFDIO_WRITEPROTECT_MODE_DONTWAKE;
          SPDLOG_TRACE("virtual_memory_manager: msync() - block index - {}", (size_t) (block_address - (size_t) m_region_start_address) / m_block_size);
          SPDLOG_TRACE("virtual_memory_manager: msync() - m_block_size - {}", m_block_size);
          if (ioctl(m_uffd, UFFDIO_WRITEPROTECT, &uffdio_writeprotect) == -1){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: msync() - Error ioctl-UFFDIO_WRITEPROTECT - {}", strerror(errno));
            exit(-1);
          }
          SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: msync() - ioctl-UFFDIO_WRITEPROTECT done");
          //*/
          // std::cout << "done wp-ing block\n";
          int sub_region_index = ((uint64_t) block_address) % num_handling_threads;
          clean_lru[sub_region_index].push_front((uint64_t)block_address);
        }
        // }
      }
      // for (int i = 0 ; i < num_handling_threads; i++){
      dirty_lru[sub_region_index].clear();

      // 2) Commit stashed blocks
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: msync() - Msync Commit Stashed Blocks");
      std::vector<uint64_t> stash_vector(stash_set[sub_region_index].begin(), stash_set[sub_region_index].end());
#endif
#pragma omp parallel for shared(m_block_storage)
      for (auto stash_iterator = stash_vector.begin(); stash_iterator != stash_vector.end(); ++stash_iterator){
        // block_storage block_storage_local(*m_block_storage);
        void* block_address = (void*) *stash_iterator;
        uint64_t block_index = ((uint64_t) block_address - (uint64_t) m_region_start_address) / m_block_size;
#pragma omp critical
        {
          std::string block_hash = /* block_storage_local.*/ m_block_storage->commit_stash_block(block_index);
          if (block_hash.empty()){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error committing stash block with address: {} - {}", (uint64_t) block_address, strerror(errno));
            exit(-1);
          }
          blocks_ids[block_index] = block_hash;
        }
      }

#ifdef SIGACTION
      stash_set.clear();
      update_metadata();
#endif
#ifdef USERFAULTFD
      stash_set[sub_region_index].clear();
      update_metadata(sub_region_index);

      struct stat st_dev_null;
      if (fstat(0,&st_dev_null) != 0){
        int dev_null_fd = ::open("/dev/null",O_RDWR);
      }
/*
      struct uffdio_writeprotect uffdio_writeprotect;
      uffdio_writeprotect.range.len = (uint64_t) m_block_size;
      uffdio_writeprotect.mode = 0;
      for (auto dirty_lru_iterator = dirty_lru_vector.begin(); dirty_lru_iterator != dirty_lru_vector.end(); ++dirty_lru_iterator){
        void* block_address = (void*) *dirty_lru_iterator;
        uffdio_writeprotect.range.start = (uint64_t) block_address;
        if (ioctl(m_uffd, UFFDIO_WRITEPROTECT, &uffdio_writeprotect) == -1){
          SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: msync() - Error ioctl-UFFDIO_WRITEPROTECT - {}", strerror(errno));
          exit(-1);
        }
      }
//*/
#endif
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: msync() - done");
    }

#ifdef SIGACTION
    void handler(int sig, siginfo_t *si, void *ctx_void_ptr){

      //const std::lock_guard<std::mutex> lock(sig_handler_mutex);
      // Get and assert faulting address
      SPDLOG_TRACE("virtual_memory_manager: handler() - start");
      uint64_t fault_address = (uint64_t) si->si_addr;
      uint64_t start_address = (uint64_t) m_region_start_address;
      uint64_t block_index = (fault_address - start_address) / m_block_size;
      uint64_t block_address = start_address + block_index * m_block_size;
      SPDLOG_TRACE("virtual_memory_manager: handler() - Faulted on block: {}", block_index);
      //SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: handler() - Faulted on block address: {}", block_address - start_address);
      /*
      for(auto i : present_blocks) {
        std::cout << "indices: " << (i - start_address) / m_block_size << std::endl;
      }
      */
      // std::cout << "thread: " << omp_get_thread_num() << " Faulted on block: " << (block_index % num_locks) << std::endl;
      // const std::lock_guard<std::mutex> lock(blocks_locks[block_index]); // lock(blocks_locks[block_index % num_locks]);
      // std::cout << "thread: " << omp_get_thread_num() << " grabbed lock number: " << (block_index % num_locks) << std::endl;
      /*
         if (fault_address < (uint64_t) start_address || fault_address >= (uint64_t) start_address + m_region_max_capacity){
         SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Faulting address out of range");
         SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Faulting address: {}", (uint64_t) fault_address);
         SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Start: {}", (uint64_t) start_address);
         SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "End: {}", (uint64_t) start_address + m_region_max_capacity);
         exit(-1);
         }
        //*/
      // Handle block fault
      ucontext_t *ctx = (ucontext_t *) ctx_void_ptr;
      bool is_write_fault = ctx->uc_mcontext.gregs[REG_ERR] & 0x2;

      if (m_read_only && is_write_fault) {
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: write fault on a read-only region");
        exit(-1);
      }

      if (present_blocks.find((uint64_t) block_address) != present_blocks.end()){ // Block is present in-memory (just change prot and LRU if needed)
        SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: handler() - Block present in memory");
        if (is_write_fault){
          // Move from clean_lru to dirty_lru
          clean_lru.remove((uint64_t) block_address);
          dirty_lru.push_front((uint64_t) block_address);
          if (stash_set.find(block_address) != stash_set.end()){
            // std::cout << "STASHED TO CLEAN TO DIRTY" << std::endl;
            if (!m_block_storage->unstash_block(block_index)){
              SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error unstashing block with index = {}", block_index);
              exit(-1);
            }
            stash_set.erase(block_address);
          }
        }
        int mprotect_stat = mprotect((void*) block_address, m_block_size, PROT_READ | PROT_WRITE);
        if (mprotect_stat == -1){
          SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: mprotect error for block with address: {} {}", (uint64_t) block_address, strerror(errno));
          exit(-1);
        }
      }
      else{ // block is not present in-memory
        SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: handler() - Block is not present in memory");
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
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error shm_open - {}", strerror(errno));
          }
          int trunc_status = ftruncate(shm_fd, m_block_size);
          if (trunc_status == -1){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error ftruncate - {}", strerror(errno));
          }
          // shm_unlink
          if (shm_unlink(block_name.c_str()) == -1){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error shm_unlink - {}", strerror(errno));
            exit(-1);
          }
          // mmap temporary location
          void* temp_buffer =  mmap(nullptr, m_block_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
#else

          void* temp_buffer =  mmap(nullptr, m_block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
          if (temp_buffer == MAP_FAILED){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error mmap temp - {}", strerror(errno));
            exit(-1);
          }

          // read block content into temporary buffer
          backing_block_fd = open(backing_block_path.c_str(), O_RDONLY);
          if (backing_block_fd == -1){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error opening backing block {} for address {} - {}", backing_block_path, block_address, strerror(errno));
            exit(-1);
          }
#ifdef USE_COMPRESSION
          // std::cout << "USING COMPRESSION DECOMPRESSING" << std::endl;
          if (stash_backing_block_path.empty()){
            // std::cout << "Reading backing block: " << backing_block_path << std::endl;
          
            size_t compressed_block_size = utility::get_file_size(backing_block_path.c_str());
            if (compressed_block_size > m_block_size){
              SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error backing block {} size {} is larger than expected block size {}", backing_block_path, compressed_block_size, m_block_size);
              exit(-1);
            }
            void* const read_buffer = mmap(nullptr, compressed_block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); // malloc(compressed_block_size);
            if (pread(backing_block_fd, read_buffer, compressed_block_size, 0) == -1){
              SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error reading backing block {} for address {} - {}", backing_block_path, block_address, strerror(errno));
              exit(-1);
            }
            size_t decompressed_size = utility::decompress(read_buffer, temp_buffer, compressed_block_size);
            // free(read_buffer);
            int munmap_status = munmap(read_buffer, compressed_block_size);
            if (munmap_status == -1){
                SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error munmapping read buffer decompression {}", strerror(errno));
            }
          }
          else{
            if (pread(backing_block_fd, temp_buffer, m_block_size, 0) == -1){
              SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error reading backing block {} for address {} - {}", backing_block_path, block_address, strerror(errno));
              exit(-1);
            }
            // std::cout << "Reading stashed backing block: " << backing_block_path << std::endl;
          }
#else

          if (pread(backing_block_fd, temp_buffer, m_block_size, 0) == -1){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error reading backing block {} for address {} - {}", backing_block_path, block_address, strerror(errno));
            exit(-1);
          }
#endif

          if (::close(backing_block_fd) == -1){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error closing backing block {} - {}", backing_block_path, strerror(errno));
            exit(-1);
          }

#ifndef __linux__
          // mmap original block
          void *mmap_block_address = mmap((void*) block_address, m_block_size, prot, MAP_PRIVATE | MAP_FIXED, shm_fd,0);
#else
          if (mprotect(temp_buffer, m_block_size, prot) != 0){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error updating permissions on temporary buffer for block {}", block_address);
            exit(-1);
          }
          void *mmap_block_address = mremap(temp_buffer, m_block_size, m_block_size, MREMAP_FIXED | MREMAP_MAYMOVE, block_address);
#endif
          if (mmap_block_address == MAP_FAILED){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error remapping address {}", block_address);
            exit(-1);
          }

#ifndef __linux__
          // unmap temp buffer
          int munmap_status = munmap(temp_buffer, m_block_size);
          if (munmap_status == -1){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error unmapping temp buffer {} for faulting block address {}", (uint64_t) temp_buffer, block_address);
            exit(-1);
          }

          // close shm_fd
          if (::close(shm_fd) == -1){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error closing shm_fd - {}", strerror(errno));
            exit(-1);
          }
#endif
          // unstash block
          if ((!stash_backing_block_path.empty()) && is_write_fault){
            // std::cout << "STASHED TO DIRTY: " << block_index << std::endl;
            if(!m_block_storage->unstash_block(block_index)){
              SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error un-stashing block with index = {}", block_index);
              exit(-1);
            }
            stash_set.erase(block_address);
          }
        }
        else{ // No backing block yet, just change mprotect
          if (mprotect((void*) block_address, m_block_size, prot) == -1){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error changing PROT for block {} - {}", block_address, strerror(errno));
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
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: handler() - done");
    }
#endif

#ifdef USERFAULTFD
    void* handler(uint64_t sub_region_index){
      SPDLOG_TRACE("virtual_memory_manager: handler() - start");
      // std::cout << "Starting handler FUNC in VMM\n";
      // printf("uffd_active %d\n", uffd_active);
      // printf("Starting handler thread with ID %d sub_region_index %d\n", (uint64_t) syscall(SYS_gettid), sub_region_index);
      while (uffd_active){
        /* debug++;
           if (debug % 100000 == 0){
           // printf("In while from thread %ld\n", (uint64_t) syscall(SYS_gettid));
           printf("uffd_active true from thread %ld\n",(uint64_t) syscall(SYS_gettid));
           } */
        // printf("THREAD %ld Checking if Queue empty\n", (uint64_t) syscall(SYS_gettid));
        // if (!fault_events_queue->is_empty()){
        // printf("Waiting on handler_mutex_global Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
        // const std::lock_guard<std::mutex> lock(handler_mutex_global);
        // printf("Aquired handler_mutex_global handler Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
        // if (!fault_events_queue.empty()){
        // Get and assert faulting address
        SPDLOG_LOGGER_INFO(spdlog::default_logger(), "Dequeing from thread {}", (uint64_t) syscall(SYS_gettid));
        utility::fault_event fevent = events_queues[sub_region_index].dequeue();
        if (fevent.address == 0){
          // std::cout << "Zero Address\n";
          // printf("Got address zero from thread %ld \n", (uint64_t) syscall(SYS_gettid));
          break;
        }
        std::chrono::time_point<std::chrono::system_clock> ts = std::chrono::system_clock::now();
        // std::cout << "Dequeue At: " << std::chrono::duration_cast<std::chrono::microseconds>(ts.time_since_epoch()).count() << std::endl;
        // dequeue_ts.push_back(std::chrono::duration_cast<std::chrono::microseconds>(ts.time_since_epoch()).count());
        // auto start = std::chrono::high_resolution_clock::now();

        uint64_t fault_address = fevent.address; // (uint64_t) (msg.arg.pagefault.address); // &~(m_block_size - 1));
        // printf("Handling in VMM from thread %ld for address %ld \n", (uint64_t) syscall(SYS_gettid), fault_address);
        uint64_t start_address = (uint64_t) m_region_start_address;
        uint64_t block_index = (fault_address - start_address) / m_block_size;
        uint64_t block_address = start_address + block_index * m_block_size;
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: handler() - Faulted on block: {}", block_index);
      //SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: handler() - Faulted on block address: {}", block_address - start_address);
      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: handler() - present_blocks indices: {}", present_blocks[sub_region_index].size());

        // Identify fault type
        bool is_wp_fault = fevent.is_wp_fault;
        bool is_write_fault = fevent.is_write_fault;
        // uint64_t sub_region_index = block_address % num_handling_threads;
        // printf("Hello from thread %ld fault_address %ld block address %ld is_wp_fault %d\n",(uint64_t) syscall(SYS_gettid), fault_address, block_address, (int) is_wp_fault);
        /* is_wp_fault = (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP);
           is_write_fault = ((!is_wp_fault) && (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE)); */
        // const std::lock_guard<std::mutex> lock(sub_regions_mutex_list[sub_region_index]);
        if ((std::find(present_blocks[sub_region_index].begin(), present_blocks[sub_region_index].end(), block_address) != present_blocks[sub_region_index].end()) && !is_wp_fault){
          // std::cout << "Address found, continuing ...\n";
          continue;
        }
        // Handling
        // std::cout << "Identifier: " << this << std::endl;
        // printf("Starting address: %ld blocks_ids address: %ld Thread ID: %ld\n", (uint64_t) m_region_start_address, (uint64_t) &blocks_ids[0], (uint64_t) syscall(SYS_gettid));
        if (is_wp_fault){
          SPDLOG_LOGGER_INFO(spdlog::default_logger(), "WP FAULT: Handling WP from thread {} for address {}", (uint64_t) syscall(SYS_gettid), fault_address);
          if (m_read_only){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: write fault on a read-only region");
            exit(-1);
          }
          // std::cout << "WP Fault Being Handled\n";
          // Move from clean_lru to dirty_lru
          clean_lru[sub_region_index].remove((uint64_t) block_address);
          dirty_lru[sub_region_index].push_front((uint64_t) block_address);
          if (stash_set[sub_region_index].find(block_address) != stash_set[sub_region_index].end()){
            // std::cout << "STASHED TO CLEAN TO DIRTY" << std::endl;
            if (!m_block_storage->unstash_block(block_index)){
              SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error unstashing block with index {}", block_index);
              exit(-1);
            }
            stash_set[sub_region_index].erase(block_address);
          }
          // Write-unprotect
          // std::cout << "write-protect fault of present page with address: " << block_address << std::endl;
          is_valid_uffd(m_uffd);
          struct uffdio_writeprotect uffdio_writeprotect;
          uffdio_writeprotect.range.start = block_address;
          uffdio_writeprotect.range.len = m_block_size;
          uffdio_writeprotect.mode = 0; // UFFDIO_WRITEPROTECT_MODE_DONTWAKE;
          if (ioctl(m_uffd, UFFDIO_WRITEPROTECT, &uffdio_writeprotect) == -1){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: handler() - Error ioctl-UFFDIO_WRITEPROTECT - {}", strerror(errno));
            exit(-1);
          }
          SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: handler() - ioctl-UFFDIO_WRITEPROTECT done");
           // TODO: Single line below:
           // Possible fix for hanging? This should ensure queue is enqued correctly in the UFFD thread.
           // This is better for passing the Snapshot test cases, but there are still issues with page eviction.
          events_queues[sub_region_index].remove_processed(fevent);
        }
        else{ // std::cout << "BEFORO Handler 420" << std::endl;
          SPDLOG_LOGGER_INFO(spdlog::default_logger(), "NOT WP FAULT");
          if (present_blocks[sub_region_index].find(block_address) == present_blocks[sub_region_index].end()){
            // std::cout << "Handler 420" << std::endl;
            evict_if_needed(sub_region_index);
            // Check if backing block exists
            int backing_block_fd = -1;
            std::string backing_block_path = ""; // printf("Handler 424 %d\n", syscall(SYS_gettid)); // std::cout << "Handler 424\n";
            std::string stash_backing_block_path = m_block_storage->get_block_stash_path(block_index); // std::cout << "Handler 425" << std::endl;
            std::string blocks_path = m_block_storage->get_blocks_path(); // std::cout << "Handler 426" << std::endl;
            // std::cout << "Handler 427" << std::endl;
            // std::cout << "Handler 427 DASH NEW" << std::endl;
            // std::cout << blocks_ids[block_index] << std::endl;
            // std::cout << "Handler 427 AFTER PRINT" << std::endl;
            // std::cout << "block_index = " << block_index << std::endl;
            if (!stash_backing_block_path.empty()){ // std::cout << "Handler 427 + 1" << std::endl;
              // std::cout << "Getting block: " << block_index << " from stash " << stash_backing_block_path << std::endl;
              backing_block_path = stash_backing_block_path;
            }
            else if(blocks_ids[block_index].compare(EMPTY_BLOCK_HASH) != 0){ // std::cout << "Handler 427 + 2" << std::endl;
              // std::cout << "Getting block: " << block_index << " from blocks " << blocks_ids[block_index] << std::endl;
              backing_block_path = m_block_storage->get_block_full_path(block_index, blocks_ids[block_index]) + "/" + blocks_ids[block_index];
            }  // std::cout << "Handler 436" << std::endl;
            bool is_zero_page = false;
            struct uffdio_copy uffdio_copy;
            if (!backing_block_path.empty()){ // TODO: Handle special case where block metadata exists but block physically not there (GC or accidental loss)
              // std::cout << "block exists" << std::endl;
              /* void* temp_buffer =  mmap(nullptr, m_block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                 if (temp_buffer == MAP_FAILED){
                 SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error mmap temp {}", strerror(errno));
                 exit(-1);
                 } */

              // read block content into temporary buffer
              backing_block_fd = open(backing_block_path.c_str(), O_RDONLY);
              if (backing_block_fd == -1){
                SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error opening backing block {} for address {} - {}", backing_block_path, block_address, strerror(errno));
                exit(-1);
              }
#ifdef USE_COMPRESSION
              // std::cout << "USING COMPRESSION DECOMPRESSING" << std::endl;
              // std::cout << "Backing block path: " << backing_block_path.c_str() << std::endl;
              // printf("Starting address: %ld blocks_ids address: %ld Thread ID: %ld", (uint64_t) m_region_start_address, (uint64_t) &blocks_ids[0], (uint64_t) syscall(SYS_gettid));
              size_t compressed_block_size = utility::get_file_size(backing_block_path.c_str());
              void* const read_buffer = mmap(nullptr, compressed_block_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); // malloc(compressed_block_size);
              if (pread(backing_block_fd, read_buffer, compressed_block_size, 0) == -1){
                SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error reading backing block {} for address {} - {}", backing_block_path, block_address, strerror(errno));
                exit(-1);
              }
              size_t decompressed_size = utility::decompress(read_buffer, (void*)(((uint64_t) temp_buffer) + (sub_region_index * m_block_size)), compressed_block_size);
              // free(read_buffer);
              int munmap_status = munmap(read_buffer, compressed_block_size);
              if (munmap_status == -1){
                 SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error munmapping read buffer decompression {}", strerror(errno));
              }
#else
              // std::cout << "NOT USING COMPRESSION" << std::endl;
              if (pread(backing_block_fd, (void*)( ((uint64_t)temp_buffer) + (sub_region_index * m_block_size)), m_block_size, 0) == -1){
                SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error closing backing block {} for address {} - {}", backing_block_path, block_address, strerror(errno));
                exit(-1);
              }
#endif

              if (::close(backing_block_fd) == -1){
                exit(-1);
              }

              // struct uffdio_copy uffdio_copy;
              is_valid_uffd(m_uffd);
              uffdio_copy.src = (unsigned long) (((uint64_t) temp_buffer) + (sub_region_index * m_block_size));
              uffdio_copy.dst = (unsigned long) block_address;
              uffdio_copy.len = m_block_size;
              uffdio_copy.mode = is_write_fault ? UFFDIO_COPY_MODE_DONTWAKE : (UFFDIO_COPY_MODE_WP | UFFDIO_COPY_MODE_DONTWAKE);
              uffdio_copy.copy = 0;
              if (ioctl(m_uffd, UFFDIO_COPY, &uffdio_copy) == -1){
                SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: handler() - Error ioctl-UFFDIO_COPY - {}", strerror(errno));
                exit(-1);
              }
              SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: handler() - ioctl-UFFDIO_COPY done");
            }
            else{
              /* char* tmp_buff;
                 if (posix_memalign((void**)&tmp_buff, m_block_size, m_block_size)) {
                 SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error posix_memalign - {}", strerror(errno));
                 }
                 void *addr = mmap((void *) tmp_buff, m_block_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
                 if (addr == MAP_FAILED){
                 SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error mmap zero page - {}", strerror(errno));
                 exit(-1);
                 } */
              // printf("TEMP ADDRESS %ld blocks_ids %ld m_block_size %ld from thread %ld\n", (uint64_t) addr, (uint64_t) &blocks_ids[0], m_block_size , (uint64_t) syscall(SYS_gettid));
              // struct uffdio_copy uffdio_copy;
              if (is_write_fault){
                is_valid_uffd(m_uffd);
                struct uffdio_zeropage uffdio_zeropage;
                uffdio_zeropage.range.start = block_address;
                uffdio_zeropage.range.len = m_block_size;
                uffdio_zeropage.mode = UFFDIO_ZEROPAGE_MODE_DONTWAKE;
                if (ioctl(m_uffd, UFFDIO_ZEROPAGE, &uffdio_zeropage) == -1){
                  SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error ioctl-UFFDIO_ZEROPAGE for Zero-page write fault - {}", strerror(errno));
                  exit(-1);
                }
                SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: handler() - ioctl-UFFDIO_ZEROPAGE done");
              }
              else{
                is_valid_uffd(m_uffd);
                uffdio_copy.src = (unsigned long) zero_page;
                uffdio_copy.dst = (unsigned long) block_address;
                uffdio_copy.len = m_block_size;
                uffdio_copy.mode = UFFDIO_COPY_MODE_WP | UFFDIO_COPY_MODE_DONTWAKE;;
                uffdio_copy.copy = 0;
                if (ioctl(m_uffd, UFFDIO_COPY, &uffdio_copy) == -1){
                  SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error ioctl-UFFDIO_COPY for zero page - {}", strerror(errno));
                  exit(-1);
                }
                SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: handler() - ioctl-UFFDIO_COPY done");
              }

              // std::cout << "uffdio_copy.copy = " << uffdio_copy.copy << std::endl;
              is_zero_page = true;
              /* if (munmap(addr, m_block_size) == -1){
                 SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error unmapping temporary buffer - {}", strerror(errno));
                 exit(-1);
                 } */
            }
            if (is_write_fault /* && is_zero_page */){
              dirty_lru[sub_region_index].push_front(block_address);
            }
            else{
              clean_lru[sub_region_index].push_front(block_address);
            }
            present_blocks[sub_region_index].insert(block_address);
            events_queues[sub_region_index].remove_processed(fevent);
            is_valid_uffd(m_uffd);
            struct uffdio_range uffdio_range;
            uffdio_range.start = block_address;
            uffdio_range.len = m_block_size;
            if (ioctl(m_uffd, UFFDIO_WAKE, &uffdio_range) == -1){
              SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error ioctl-UFFDIO_WAKE - {}", strerror(errno));
              exit(-1);
            }
            SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: handler() - ioctl-UFFDIO_WAKE done");
          }
        }
        /* std::chrono::time_point<std::chrono::system_clock> */ ts = std::chrono::system_clock::now();
        // std::cout << "Page Fault Handled At: " << std::chrono::duration_cast<std::chrono::microseconds>(ts.time_since_epoch()).count() << std::endl;
        // handled_ts.push_back(std::chrono::duration_cast<std::chrono::microseconds>(ts.time_since_epoch()).count());
        // auto stop = std::chrono::high_resolution_clock::now();
        // auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        // printf("Handling took: %ld\n", duration.count());
        // }
        // printf("Releasing handler_mutex_global handler Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));

        // printf("DONE Handling in VMM from thread %ld for address %ld \n", (uint64_t) syscall(SYS_gettid), fault_address);
        // }
        // printf("THREAD %ld Queue empty\n", (uint64_t) syscall(SYS_gettid));
      }
      // printf("THREAD %ld QUITTING HERE\n", (uint64_t) syscall(SYS_gettid));
      return NULL;
      // END: Poll for page fault events
      // -------------------------------
      SPDLOG_TRACE("virtual_memory_manager: handler() - done");
    }
#endif

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
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error opening size file path at {}", size_file_name);
        return (size_t) -1;
      }
      if (!std::getline(size_file, size_string)){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error reading file");
        return (size_t) -1;
      }
      size_file.close();
      try {
        size_t size = std::stol(size_string);
        return size;
      }
      catch (const std::invalid_argument& ia){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error parsing version size from file - {}", ia.what());
        return (size_t) -1;
      }
    }

    size_t static version_block_size(std::string version_path){
      std::string blocks_path_file_name = std::string(version_path) + "/_blocks_path";
      std::ifstream blocks_path_file;
      std::string blocks_dir_path;
      
      blocks_path_file.open(blocks_path_file_name);
      if (!blocks_path_file.is_open()){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error opening blocks file path at {}", blocks_path_file_name);
        exit(-1);
      }
      if (!std::getline(blocks_path_file, blocks_dir_path)){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error reading blocks path file");
        exit(-1);
      } 
      return block_storage::get_version_block_granularity(blocks_dir_path);
    }

    size_t current_region_capacity(){
      return m_region_max_capacity;
    }

    bool snapshot(const char* version_metadata_path){
      //SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: snapshot() 1 - {}", ((size_t*) get_region_start_address())[0]);
      std::string snapshot_metadata_path = std::string(version_metadata_path) + "/_metadata";
      std::string m_temp_current_metadata_path = m_version_metadata_path;


      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: snapshot() - start");
      // Create new version metadata directory
      if(utility::directory_exists(version_metadata_path)){
        if (utility::file_exists(snapshot_metadata_path.c_str())){
          spdlog::warn("virtual_memory_manager: Version metadata directory already exists");
          return false;
        }
      }

      else if (!utility::create_directory(version_metadata_path)){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Failed to create version metadata directory at {} - {}", version_metadata_path, strerror(errno));
        return false;
      }

      //SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: snapshot() 2 - {}", ((size_t*) get_region_start_address())[0]);
      // temporarily change metadata file descriptor
      // int temp_metada_fd = metadata_fd;
      m_version_metadata_path = std::string(version_metadata_path);

      int metadata_fd = ::open(snapshot_metadata_path.c_str(), O_RDWR | O_CREAT, (mode_t) 0666);
      int close_status = ::close(metadata_fd);

      //SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: snapshot() 3 - {}", ((size_t*) get_region_start_address())[0]);
      msync();
      m_version_metadata_path = m_temp_current_metadata_path;
      // metadata_fd = temp_metada_fd;

      //SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: snapshot() 4 - {}", ((size_t*) get_region_start_address())[0]);
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

      SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: snapshot() - done");
      return true;
    }

    size_t get_block_size(){
      return m_block_size;
    }

    int close(){
      //  << "ByeBye VMM" << std::endl;
      msync();
      std::set<uint64_t>::iterator it;

#ifdef SIGACTION
      for (it = present_blocks.begin(); it != present_blocks.end(); ++it) {
#endif

#ifdef USERFAULTFD
        for (int i = 0; i < num_handling_threads; i++){
          for (it = present_blocks[i].begin(); it != present_blocks[i].end(); ++it) {
#endif

            void* address = (void*) *it;
            int status = munmap(address, m_block_size);
            if (status == -1){
              SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error unmapping region with address {} - {}", *it, strerror(errno));
              return -1;
            }
          }
#ifdef USERFAULTFD
        }
#endif
        delete [] blocks_ids;
        // delete [] blocks_locks;
        delete m_block_storage;
        m_region_start_address = nullptr;
#ifdef USERFAULTFD
        stop_handler_thread();
#endif
        return 0;
      }

#ifdef USERFAULTFD
      void set_uffd(uint64_t uffd){
        m_uffd = uffd;
      }

      static void* handler_helper(void *context){
        printf("Starting Handler HELPER from %ld\n", (uint64_t) syscall(SYS_gettid));
        int sub_region_index = ((virtual_memory_manager *)context)->get_next_sub_region();
        return ((virtual_memory_manager *)context)->handler(sub_region_index);
      }

      uint64_t get_block_address(uint64_t fault_address){
        uint64_t start_address = (uint64_t) m_region_start_address;
        uint64_t block_index = (fault_address - start_address) / m_block_size;
        uint64_t block_address = start_address + block_index * m_block_size;
        return block_address;
      }

      void add_page_fault_event(utility::fault_event fevent){
        // printf("Waiting on add_event_mutex Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
        // const std::lock_guard<std::mutex> lock(add_event_mutex);
        // printf("Aquired add_event_mutex Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
        // printf("Page Fault Event Added to queue for address %ld\n", fevent.address);
        uint64_t start_address = (uint64_t) m_region_start_address;
        uint64_t block_index = (fevent.address - start_address) / m_block_size;
        uint64_t sub_region_index = block_index % num_handling_threads;
        printf("Page Fault Event Added to queue for address %ld sub_region_index %ld num_handling_threads %ld\n", fevent.address, sub_region_index, num_handling_threads);
        // auto start = std::chrono::high_resolution_clock::now();
        if (!events_queues[sub_region_index].found(fevent)){
          std::cout << "NOT FOUND" << std::endl ;
          events_queues[sub_region_index].enqueue(fevent);
        }
        else {
          std::cout << "FOUND" << std::endl ;
        }
        // auto stop = std::chrono::high_resolution_clock::now();
        // auto add_time = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
        // printf("Adding to queue took: %ld\n", add_time.count());
        // printf("Releasing add_event_mutex Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
      }

      void add_page_fault_event_all(utility::fault_event fevent){
        for (int i = 0; i < num_handling_threads; i++){
          events_queues[i].enqueue(fevent);
        }
      }

      void start_handler_thread(){
        // std::cout << "Starting handler thread in VMM";
        for (int i = 0; i < num_handling_threads; i++){
          pthread_t fault_handling_thread;
          int status = pthread_create(&fault_handling_thread, NULL, handler_helper, (void*) this);
          if (status != 0){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: pthread_create - {}", strerror(status));
            exit(-1);
          }
          fault_handling_threads.push_back(fault_handling_thread);
        }
        // printf("Done creating %d handler threads\n",fault_handling_threads.size());
      }

      void stop_handler_thread(){
        // std::cout << "VMM: stop_handler_thread before pthread_join\n";
        uffd_active = false;
        // std::this_thread::sleep_for (std::chrono::seconds(3));
        /* for (int i = 0; i < num_handling_threads; i++){
           add_page_fault_event({.address = 0, .is_wp_fault = false, .is_write_fault = false});
           } */

        for (int i = 0; i < num_handling_threads; i++){
          // printf("VMM: stop_handler_thread before pthread_join for thread %d\n", i);
          int status = pthread_join(fault_handling_threads[i],NULL);
          if (status != 0){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error pthread_join - ", strerror(status));
            exit(-1);
          }
          // printf("VMM: stop_handler_thread after pthread_join for thread %d\n", i);
        }
        // std::cout << "VMM: stop_handler_thread after pthread_join\n";
      }

      void deactivate_uffd_thread(){
        // std::cout << "START: deactivate_uffd_thread" << std::endl;
        uffd_active = false;
        /* char bye[5] = "bye";
           write(uffd_pipe[1], bye, 3); */
        // std::cout << "END: deactivate_uffd_thread" << std::endl;
      }

      int get_next_sub_region(){
        return ++next_sub_region;
      }
#endif

    private:
      void* m_region_start_address;
      size_t m_block_size;
      size_t m_region_max_capacity;
      size_t m_max_mem_size;
      std::string m_version_metadata_path;
      bool m_read_only;
      int metadata_fd;

      std::string *blocks_ids;

#ifdef SIGACTION
      std::list<uint64_t> clean_lru;
      std::list<uint64_t> dirty_lru;
      std::set<uint64_t> stash_set;
      std::set<uint64_t> present_blocks;

      const size_t MAX_MEM_DEFAULT_BLOCKS = 16384;

      // std::mutex* blocks_locks;
      // size_t num_locks = 2048;
      std::mutex sig_handler_mutex;
#endif

#ifdef USERFAULTFD
      int prot;
      std::vector<std::list<uint64_t>> clean_lru; // Change to sub-regions (declaration [done], usage [done])
      std::vector<std::list<uint64_t>> dirty_lru; // Change to sub-regions (declaration [done], usage [done])
      std::vector<std::set<uint64_t>> stash_set; // Change to sub-regions (declaration [done], usage [done])
      std::vector<std::set<uint64_t>> present_blocks; // Change to sub-regions (declaration [done], usage [done])
      std::vector<std::mutex> sub_regions_mutex_list;

     void *zero_page;
      void *temp_buffer;

      // temp start
      std::vector<long> dequeue_ts;
      std::vector<long> handled_ts;
      // temd end

      const size_t FILE_GRANULARITY_DEFAULT_BYTES = 2097152; // 2 MBs
      const size_t MAX_MEM_DEFAULT_BLOCKS = 16384;
      const int NUM_HANDLING_THREADS_DEFAULT = 1;
      const int NUM_MSYNC_THREADS_DEFAULT = 1;

      std::mutex handler_mutex_global;
      // utility::event_queue<utility::fault_event> fault_events_queue(1);
      //
      std::mutex* blocks_locks;
      std::mutex add_event_mutex;
      pthread_mutex_t handler_mutex;
      long m_uffd;
      std::atomic<bool> uffd_active;
      int uffd_pipe[2];
      // size_t num_locks = 2048;
      std::vector<utility::event_queue<utility::fault_event>> events_queues;
      // utility::event_queue<utility::fault_event> *fault_events_queue;
      int num_handling_threads;
      int num_msync_threads;
      std::vector<pthread_t> fault_handling_threads; // Change to sub-regions (declaration [done], usage (TODO))
      std::atomic<long> debug = 0;
      std::atomic<uint64_t> next_sub_region = -1;
#endif


      const size_t HASH_SIZE = 64;
      const std::string EMPTY_BLOCK_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

      block_storage *m_block_storage;

      bool is_valid_uffd(int uffd) {
        /*
        struct uffdio_api uffdio_api;
        uffdio_api.api = UFFD_API;
        uffdio_api.features = 0;
        //if (!(fcntl(uffd, F_GETFD) != -1 || errno != EBADF)) {
        if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1) {
          SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Invalid userfaultfd: {}", strerror(errno));
          return false;
        }
        */
        return true;
      }

#ifdef SIGACTION
      void evict_if_needed(){
        void* to_evict;
        if ((present_blocks.size()*m_block_size) >= m_max_mem_size){
          SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: evict_if_needed() - Evicting");
          if (clean_lru.size() > 0){
            to_evict = (void*) clean_lru.back();
            SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: evict_if_needed() - Evicting clean block: {}", ((uint64_t) to_evict - (uint64_t) m_region_start_address) / m_block_size);
            clean_lru.pop_back();
          }
          else{
            // std::cout << "I am failing, bye!" << std::endl;
            to_evict = (void*) dirty_lru.back();
            dirty_lru.pop_back();
            // std::cout << "Hello from the other side" << std::endl;
            uint64_t block_index = ((uint64_t) to_evict - (uint64_t) m_region_start_address) / m_block_size;
            SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: evict_if_needed() - Stashing block: {}", block_index);
            if (!m_block_storage->stash_block(to_evict, block_index)){
              SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error stashing block with index {}", block_index);
              exit(-1);
            }
            stash_set.insert((uint64_t) to_evict);
          }

          int protect_status = mprotect(to_evict, m_block_size, PROT_NONE);
          if (protect_status == -1){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error evicting address {}", to_evict);
            exit(-1);
          }

          int madvise_status = madvise(to_evict, m_block_size, MADV_DONTNEED);
          if (madvise_status == -1){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error madvising address {}", to_evict);
            exit(-1);
          }

          present_blocks.erase((uint64_t) to_evict);
        }
      }
#endif

#ifdef USERFAULTFD
      void evict_if_needed(int sub_region_index){
        void* to_evict;
        if ((present_blocks[sub_region_index].size()*m_block_size) >= m_max_mem_size){
          SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: evict_if_needed() - Evicting");
          if (clean_lru[sub_region_index].size() > 0){
            to_evict = (void*) clean_lru[sub_region_index].back();
            SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: evict_if_needed() - Evicting clean block: {}", ((uint64_t) to_evict - (uint64_t) m_region_start_address) / m_block_size);
            clean_lru[sub_region_index].pop_back();
          }
          else{
            to_evict = (void*) dirty_lru[sub_region_index].back();
            dirty_lru[sub_region_index].pop_back();
            uint64_t block_index = ((uint64_t) to_evict - (uint64_t) m_region_start_address) / m_block_size;
            SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: evict_if_needed() - Stashing block: {}", block_index);
            if (!m_block_storage->stash_block(to_evict, block_index)){
              SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error stashing block with index {}", block_index);
              exit(-1);
            }
            stash_set[sub_region_index].insert((uint64_t) to_evict);
          }
          /* int protect_status = mprotect(to_evict, m_block_size, PROT_NONE);
             if (protect_status == -1){
             SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error evicting address {}", to_evict);
             exit(-1);
             } */
          void *evicted_addr = mmap(to_evict, m_block_size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
          if (evicted_addr == MAP_FAILED){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error evicting block with address - {}", strerror(errno));
            exit(-1);
          }
          present_blocks[sub_region_index].erase((uint64_t) to_evict);
        }
      }
#endif

#ifdef SIGACTION
      void update_metadata(){

        // std::cout << "present_blocks.size(): " << present_blocks.size() << std::endl;
        if (present_blocks.size() == 0){
          return;
        }
        size_t max_address = *present_blocks.rbegin();
#endif

#ifdef USERFAULTFD
        void update_metadata(int sub_region_index){
          // const std::lock_guard<std::mutex> lock(handler_mutex_global);
          // std::cout << "present_blocks.size(): " << present_blocks.size() << std::endl;
          if (present_blocks[sub_region_index].size() == 0){
            return;
          }
          size_t max_address = *present_blocks[sub_region_index].rbegin();
#endif

          SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: update_metadata()");

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
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error opening metadata file - {}", strerror(errno));
            exit(-1);
          }
          const auto written = ::pwrite(metadata_fd ,(void*) blocks_bytes, num_blocks*HASH_SIZE, 0);
          if (written == -1){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Failed to update metadata and mappings - {}", strerror(errno));
            exit(-1);
          }
          if (::close(metadata_fd == -1)){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error closing metadata file after update - {}", strerror(errno));
            exit(-1);
          }
          delete [] blocks_bytes;
          SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: update_metadata() - done");
        }

        void create_version_metadata(const char* version_metadata_dir_path, const char* block_storage_dir_path, size_t version_capacity, bool allow_overwrite){
          SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: create_version_metadata()");
          std::string metadata_file_name = std::string(version_metadata_dir_path) + "/_metadata";
          std::string blocks_path_file_name = std::string(version_metadata_dir_path) + "/_blocks_path";
          std::string capacity_file_name = std::string(version_metadata_dir_path) + "/_capacity";

          // Create version directory
          if (utility::directory_exists(version_metadata_dir_path)){
            if (utility::file_exists(metadata_file_name.c_str()) || utility::file_exists(blocks_path_file_name.c_str()) || utility::file_exists(capacity_file_name.c_str())){
              if (allow_overwrite){
                if (!std::filesystem::remove(std::filesystem::path(metadata_file_name)) || !std::filesystem::remove(std::filesystem::path(blocks_path_file_name)) || !std::filesystem::remove(std::filesystem::path(capacity_file_name))){
                  SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error removing existing metadata files");
                  exit(-1);
                }
                if (!utility::create_directory(version_metadata_dir_path)){
                  SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Failed to create version metadata directory at {} - {}", version_metadata_dir_path, strerror(errno));
                  exit(-1);
                }
              }
              else{
                SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Version metadata already exists");
                exit(-1);
              }
            }
          }
          else if (!utility::create_directory(version_metadata_dir_path)){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Failed to create version metadata directory at {} - {}", version_metadata_dir_path, strerror(errno));
            exit(-1);
          }
          // Create blocks metadata file
          metadata_fd = ::open(metadata_file_name.c_str(), O_RDWR | O_CREAT | O_EXCL, (mode_t) 0666);
          if (metadata_fd == -1){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error opening metadata file {} - {}", metadata_file_name, strerror(errno));
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
