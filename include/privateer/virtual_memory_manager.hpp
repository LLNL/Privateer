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

#include "block_storage.hpp"

class virtual_memory_manager {
  public:
    virtual_memory_manager(void* start_address, size_t block_size, size_t region_max_capacity, size_t max_mem_size_blocks,
                                                    std::string versioin_metadata_path, std::string blocks_path, std::string stash_path);
    virtual_memory_manager(void* addr, std::string version_metadata_path, std::string stash_path, bool read_only, size_t max_mem_size_blocks);
    ~virtual_memory_manager();
    void msync();
    void handler(int sig, siginfo_t *si, void *ctx_void_ptr);
    void* get_region_start_address();
    size_t version_capacity(std::string version_path);
    bool snapshot(const char* version_metadata_path);
  private:
    void* m_region_start_address;
    size_t m_block_size;
    size_t m_region_max_capacity;
    size_t m_max_mem_size;
    std::string m_version_metadata_path;
    bool m_read_only;
    std::list<uint64_t> clean_lru;
    std::list<uint64_t> dirty_lru;
    std::set<uint64_t> stash_set;
    std::set<uint64_t> present_blocks;
    std::string *blocks_ids;
    
    static const size_t HASH_SIZE;
    static const std::string EMPTY_BLOCK_HASH;

    block_storage *m_block_storage;

    void evict_if_needed();
    void update_metadata();
};

const size_t virtual_memory_manager::HASH_SIZE = 64;
const std::string virtual_memory_manager::EMPTY_BLOCK_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

// TODO IMPORTANT: Make create() and open() interfaces
// Create
virtual_memory_manager::virtual_memory_manager(void* start_address, size_t block_size, size_t region_max_capacity, size_t max_mem_size_blocks,
                                                    std::string version_metadata_path, std::string blocks_path, std::string stash_path){
  m_block_size = block_size;
  m_region_max_capacity = region_max_capacity;
  size_t max_mem_size_bytes = max_mem_size_blocks * m_block_size;
  m_max_mem_size = ((size_t)(max_mem_size_bytes / m_block_size)) * m_block_size;
  std::cout << "m_max_mem_size = " << m_max_mem_size << std::endl;
  m_version_metadata_path = version_metadata_path;


  m_block_storage = new block_storage(blocks_path, stash_path, block_size);
  
  size_t num_blocks = m_region_max_capacity / m_block_size;
  std::cout << "num_blocks: " << num_blocks << std::endl;
  blocks_ids = new std::string[num_blocks];

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
  
  for (size_t i = 0 ; i < num_blocks ; i++){
    blocks_ids[i] = EMPTY_BLOCK_HASH;
  }

  m_read_only = false;

  // Define the signal and associate with handler
  /* struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = handler;
  if (sigaction(SIGSEGV, &sa, NULL) == -1)
    std::cerr << "Error: sigaction failed" << std::endl; */
};

// Open
virtual_memory_manager::virtual_memory_manager(void* addr, std::string version_metadata_path, std::string stash_path, bool read_only, size_t max_mem_size_blocks){
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
    std::cerr << "Privateer373: mmap error - " << strerror(errno)<< std::endl;
    exit(-1);
  }
  std::cout << "num_blocks: " << num_blocks << std::endl;
  blocks_ids = new std::string[num_blocks];
  char* metadata_content = new char[metadata_size];
  size_t read = ::pread(metadata_fd, (void*) metadata_content, metadata_size, 0);
  if (read == -1){
    std::cerr << "virtual_memory_manager: Error reading metadata - " << strerror(errno) << std::endl;
    exit(-1);
  }

  std::string all_hashes(metadata_content, metadata_size);
  uint64_t offset = 0;
  // std::cout << "Privateer: Metadata size = " << metadata_size  << std::endl;
  for (size_t i = 0; i < metadata_size; i += HASH_SIZE){
    // std::cout << "Privateer: Initializing blocks and regions, iteration no. " << i << std::endl;
    std::string block_hash(all_hashes, i, HASH_SIZE);
    blocks_ids[i / HASH_SIZE] = block_hash;
  }
  delete [] metadata_content;

  size_t max_mem_size_bytes = max_mem_size_blocks * m_block_size;
  m_max_mem_size = ((size_t)(max_mem_size_bytes / m_block_size)) * m_block_size;

  std::cout << "m_max_mem_size = " << m_max_mem_size << std::endl;
  
}

void virtual_memory_manager::handler(int sig, siginfo_t *si, void *ctx_void_ptr){
  
  // Evict if needed

  // evict_if_needed();

  // Get and assert faulting address
  uint64_t fault_address = (uint64_t) si->si_addr;
  uint64_t start_address = (uint64_t) m_region_start_address;
  if (fault_address < (uint64_t) start_address || fault_address >= (uint64_t) start_address + m_region_max_capacity){
    std::cerr << "Error: Faulting address out of range" << std::endl;
    exit(-1);
  }
  // Handle page fault
  ucontext_t *ctx = (ucontext_t *) ctx_void_ptr;
  uint64_t block_index = (fault_address - start_address) / m_block_size;
  uint64_t block_address = start_address + block_index * m_block_size;
  bool is_write_fault = ctx->uc_mcontext.gregs[REG_ERR] & 0x2;
  
  if (present_blocks.find((uint64_t) block_address) != present_blocks.end()){
    if (is_write_fault){
      // Move from clean_lru to dirty_lru
      clean_lru.remove((uint64_t) block_address);
      dirty_lru.push_front((uint64_t) block_address);
    }
    int mprotect_stat = mprotect((void*) block_address, m_block_size, PROT_READ | PROT_WRITE);
    if (mprotect_stat == -1){
      std::cerr << "virtual_memory_manager: mprotect error for block with address: " << (uint64_t) block_address << " " << strerror(errno) << std::endl;
      exit(-1);
    }
  }
  else{
    evict_if_needed();
    // Read backing block if exists
    int backing_block_fd = -1;
    std::string backing_block_path = "";
    std::string stash_backing_block_path = m_block_storage->get_block_stash_path(block_index); 
    std::string blocks_path = m_block_storage->get_blocks_path();
    // std::cout << "block_index = " << block_index << std::endl;
    if (!stash_backing_block_path.empty()){
      std::cout << "Getting block: " << block_index << " from stash " << stash_backing_block_path << std::endl;
      backing_block_path = stash_backing_block_path;
    }
    else if(blocks_ids[block_index].compare(EMPTY_BLOCK_HASH) != 0){
      std::cout << "Getting block: " << block_index << " from blocks " << blocks_ids[block_index] << std::endl;
      backing_block_path = m_block_storage->get_blocks_subdirectory(block_index) + "/" + blocks_ids[block_index];
    }
    
    // shm_open
    boost::uuids::uuid uuid = boost::uuids::random_generator()();
    const std::string block_name = boost::lexical_cast<std::string>(uuid);
    int shm_fd = shm_open(block_name.c_str(), O_CREAT | O_RDWR, S_IWUSR);
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
    if (temp_buffer == MAP_FAILED){
      std::cerr << "Error mmap temp: " << strerror(errno) << std::endl;
      exit(-1);
    }

    if (!backing_block_path.empty()){
      // read block content into temporary buffer
      backing_block_fd = open(backing_block_path.c_str(), O_RDONLY);
      if (backing_block_fd == -1){
        std::cerr << "virtual_memory_manager: Error opening backing block: " << backing_block_path  << " for address: " << block_address << " - " << strerror(errno) << std::endl;
        exit(-1);
      }
      if (pread(backing_block_fd, temp_buffer, m_block_size, 0) == -1){
        std::cerr << "virtual_memory_manager: Error reading backing block: " << backing_block_path << " for address: " << block_address << std::endl;
      }

      if (close(backing_block_fd) == -1){
        std::cout << "virtual_memory_manager: Error closing backing block: " << backing_block_path << " - " << strerror(errno) << std::endl;
      }
    }
    else{ // Zero page
      memset(temp_buffer, 0, m_block_size);
    }
    
    // mmap original block
    int prot = is_write_fault ? PROT_WRITE : PROT_READ;
    void *mmap_block_address = mmap((void*) block_address, m_block_size, prot, MAP_PRIVATE | MAP_FIXED, shm_fd,0);
    if (mmap_block_address == MAP_FAILED){
      std::cerr << "virtual_memory_manager: Error remapping address: " << block_address << std::endl;
      exit(-1);
    }
    // unmap temp buffer
    int munmap_status = munmap(temp_buffer, m_block_size);
    if (munmap_status == -1){
      std::cerr << "virtual_memory_manager: Error unmapping temp buffer: " << (uint64_t) temp_buffer << " for faulting block address: " << block_address << std::endl;
      exit(-1);
    }
    // close shm_fd
    if (close(shm_fd) == -1){
      std::cerr << "virtual_memory_manager: Error closing shm_fd: " << strerror(errno) << std::endl;
      exit(-1);
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
}

void virtual_memory_manager::evict_if_needed(){
  void* to_evict;
  if ((present_blocks.size()*m_block_size) >= m_max_mem_size){
    if (clean_lru.size() > 0){
        to_evict = (void*) clean_lru.back();
        std::cout << "Evicting clean block: " << ((uint64_t) to_evict - (uint64_t) m_region_start_address) / m_block_size << std::endl;
        clean_lru.pop_back();
    }
    else{
      // std::cout << "I am failing, bye!" << std::endl;
      to_evict = (void*) dirty_lru.back();
      dirty_lru.pop_back();
      // std::cout << "Hello from the other side" << std::endl;
      uint64_t block_index = ((uint64_t) to_evict - (uint64_t) m_region_start_address) / m_block_size;
      std::cout << "stashing block: " << block_index << std::endl;
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

void virtual_memory_manager::msync(){
  // 1) Write dirty_lru
  std::cout << "size of dirty LRU: "<< dirty_lru.size() << std::endl;
  #pragma omp parallel
  for (auto it = dirty_lru.begin(); it != dirty_lru.end(); ++it){
    void* block_address = (void*) *it;
    if (stash_set.find((uint64_t) block_address) == stash_set.end()){
      uint64_t block_index = ((uint64_t) block_address - (uint64_t) m_region_start_address) / m_block_size;
      std::string temporary_file_name_template = std::to_string(block_index) + "_temp_XXXXXX";
      char* name_template = (char*) temporary_file_name_template.c_str();
      int block_fd = m_block_storage->create_temporary_unique_block(name_template, block_index); // , existing_block_file_name.c_str());
      if (block_fd == -1){
        std::cerr << "virtual_memory_manager: Error creating temporary file"<< std::endl;
        exit(-1);
      }
      bool write_block_fd = true;
      bool status = m_block_storage->store_block(block_fd, block_address, write_block_fd, block_index);
      if (!status){
        std::cerr << "virtual_memory_manager: Error storing block with index " << block_index << std::endl;
        exit(-1);
      }
      
      blocks_ids[block_index] = std::string(m_block_storage->get_block_hash(block_fd));
      // Change mprotect to read_only
      int mprotect_stat = mprotect(block_address, m_block_size, PROT_READ);
      if (mprotect_stat == -1){
        std::cerr << "virtual_memory_manager: mprotect error for block with address: " << (uint64_t) block_address << " " << strerror(errno) << std::endl;
        exit(-1);
      }
      clean_lru.push_front((uint64_t)block_address);
    }
  }
  dirty_lru.clear();
  
  // 2) Commit stashed blocks
  std::cout << "SIZE OF STASH SET: " << stash_set.size() << std::endl;
  #pragma omp parallel
  for (auto it = stash_set.begin(); it != stash_set.end(); ++it){
    void* block_address = (void*) *it;
    uint64_t block_index = ((uint64_t) block_address - (uint64_t) m_region_start_address) / m_block_size;
    std::string block_hash = m_block_storage->commit_stash_block(block_index);
    if (block_hash.empty()){
      std::cerr << "virtual_memory_manager: Error committing stash block with address: " << (uint64_t) block_address << std::endl;
      exit(-1);
    }
    blocks_ids[block_index] = block_hash;
  }
  stash_set.clear();
  update_metadata();
}

// TODO: Redesign and Rewrite
bool virtual_memory_manager::snapshot(const char* version_metadata_path){
  // Create new version metadata directory
  if(utility::directory_exists(version_metadata_path)){
    std::cerr << "Error: Version metadata directory already exists" << std::endl;
    return false;
  }

  if (!utility::create_directory(version_metadata_path)){
    std::cerr << "Error: Failed to create version metadata directory" << std::endl;
  }

  // temporarily change metadata file descriptor
  // int temp_metada_fd = metadata_fd;
  std::string snapshot_metadata_path = std::string(version_metadata_path) + "/_metadata";
  std::string m_temp_current_metadata_path = m_version_metadata_path;
  m_version_metadata_path = std::string(version_metadata_path);
  // std::cout << "Privateer: Snapshotting to " << snapshot_metadata_path << std::endl;
  // TODO: Add check or create in a different way
  int metadata_fd = ::open(snapshot_metadata_path.c_str(), O_RDWR | O_CREAT, (mode_t) 0666);
  int close_status = close(metadata_fd);
  
  msync();
  m_version_metadata_path = m_temp_current_metadata_path;
  // metadata_fd = temp_metada_fd;

  // Create file to save blocks path
  std::string blocks_path_file_name = std::string(version_metadata_path) + "/_blocks_path";
  std::ofstream blocks_path_file;
  blocks_path_file.open(blocks_path_file_name);
  blocks_path_file << m_block_storage->get_blocks_path();
  blocks_path_file.close();

  // Create file to save current size
  /* std::string size_path_file_name = std::string(version_metadata_path) + "/_size";
  std::ofstream size_path_file;
  size_path_file.open(size_path_file_name);
  size_path_file << m_current_size;
  size_path_file.close(); */


  // Create file to save max. capacity
  std::string capacity_path_file_name = std::string(version_metadata_path) + "/_capacity";
  std::ofstream capacity_path_file;
  capacity_path_file.open(capacity_path_file_name);
  capacity_path_file << m_region_max_capacity;
  capacity_path_file.close();

  return true;
}

void virtual_memory_manager::update_metadata(){
  size_t num_blocks = m_region_max_capacity / m_block_size;
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
  std::cout << "update metadata to path: " << metadata_path << std::endl;
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
  if (close(metadata_fd == -1)){
    std::cerr << "Virtual Memory Manager: Error closing metadata file after update - " << strerror(errno) << std::endl;
    exit(-1);
  }
  delete [] blocks_bytes;
}

void* virtual_memory_manager::get_region_start_address(){
  return m_region_start_address;
}

size_t virtual_memory_manager::version_capacity(std::string version_path){
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

virtual_memory_manager::~virtual_memory_manager(){
  std::set<uint64_t>::iterator it;
  for (it = present_blocks.begin(); it != present_blocks.end(); ++it) {
      void* address = (void*) *it;
      int status = munmap(address, m_block_size);
      if (status == -1){
        std::cerr << "virtual_memory_manager: Error unmapping region with address: " << *it << " - " << strerror(errno) << std::endl;
        exit(-1);
      }
  }
  delete [] blocks_ids;
}

