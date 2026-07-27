#include <privateer/sigaction_virtual_memory_manager.hpp>
#include <privateer/block_storage_factory.hpp>
#include <privateer/utility/system.hpp>
#include <fstream>
#include <thread>
#include <vector>
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#ifdef USE_COMPRESSION
#include <privateer/utility/compression.hpp>
#endif

namespace {
template <typename Func>
void run_parallel_for_count(size_t count, Func&& func) {
  if (count == 0) {
    return;
  }

  size_t thread_count = std::thread::hardware_concurrency();
  if (thread_count == 0) {
    thread_count = 1;
  }
  thread_count = std::min(thread_count, count);

  std::vector<std::thread> workers;
  workers.reserve(thread_count);
  size_t chunk_size = (count + thread_count - 1) / thread_count;

  for (size_t thread_index = 0; thread_index < thread_count; ++thread_index) {
    size_t begin = thread_index * chunk_size;
    if (begin >= count) {
      break;
    }
    size_t end = std::min(count, begin + chunk_size);
    workers.emplace_back([begin, end, &func]() {
      for (size_t index = begin; index < end; ++index) {
        func(index);
      }
    });
  }

  for (auto& worker : workers) {
    worker.join();
  }
}
}

// Constructor for creating new region
sigaction_virtual_memory_manager::sigaction_virtual_memory_manager(
    void* start_address, size_t region_max_capacity, size_t block_size,
    std::string version_metadata_path, std::string blocks_path, 
    std::string stash_path, bool allow_overwrite) {
    
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), 
        "sigaction_virtual_memory_manager() - start");
    
    // Verify system page alignment
    size_t pagesize = sysconf(_SC_PAGE_SIZE);
    if (((uint64_t) start_address) % pagesize != 0) {
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), 
            "sigaction_virtual_memory_manager: start address not page aligned");
        exit(-1);
    }

    m_block_size = block_size;
    if (region_max_capacity % m_block_size != 0 && region_max_capacity != 0) {
      region_max_capacity = ((region_max_capacity / m_block_size) + 1) * m_block_size;
    }

    size_t max_mem_size_blocks = utility::get_environment_variable("PRIVATEER_MAX_MEM_BLOCKS");
    if (std::isnan((double)max_mem_size_blocks) || max_mem_size_blocks == 0) {
        max_mem_size_blocks = MAX_MEM_DEFAULT_BLOCKS;
    }

  #ifndef ENABLE_PAGE_EVICTION
    if (max_mem_size_blocks * m_block_size < region_max_capacity) {
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Page eviction not permitted");
    }
  #endif

    create_version_metadata(version_metadata_path.c_str(), blocks_path.c_str(), 
                           region_max_capacity, allow_overwrite);
    
    m_region_max_capacity = region_max_capacity;
    m_max_mem_size = max_mem_size_blocks * m_block_size;
    m_version_metadata_path = version_metadata_path;

    m_block_storage = block_storage_factory::create(blocks_path, stash_path, m_block_size);

    // mmap region with full size
    int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE;
    if (start_address != nullptr) {
        flags |= MAP_FIXED;
    }

    m_region_start_address = mmap(start_address, m_region_max_capacity, 
                                  PROT_NONE, flags, -1, 0);

    if (m_region_start_address == MAP_FAILED) {
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), 
            "sigaction_virtual_memory_manager: mmap failed");
        exit(-1);
    }

    size_t num_blocks = m_region_max_capacity / m_block_size;
    blocks_ids = new std::string[num_blocks];
    for (size_t i = 0; i < num_blocks; i++) {
        blocks_ids[i] = EMPTY_BLOCK_HASH;
    }

    struct stat st_dev_null;
    if (fstat(0, &st_dev_null) != 0) {
      int dev_null_fd = ::open("/dev/null", O_RDWR);
      (void)dev_null_fd;
    }

    m_read_only = false;
}

// Constructor for opening existing region
sigaction_virtual_memory_manager::sigaction_virtual_memory_manager(
    void* addr, std::string version_metadata_path, 
    std::string stash_path, bool read_only) {
    
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), 
        "sigaction_virtual_memory_manager() - open");
    
    m_version_metadata_path = version_metadata_path;
    
    // Read blocks path
    std::string blocks_path_file_name = m_version_metadata_path + "/_blocks_path";
    std::ifstream blocks_path_file;
    std::string blocks_dir_path;
    
    blocks_path_file.open(blocks_path_file_name);
    if (!blocks_path_file.is_open()) {
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), 
            "Error opening blocks path file");
        exit(-1);
    }
    if (!std::getline(blocks_path_file, blocks_dir_path)) {
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), 
            "Error reading blocks path file");
        exit(-1);
    }
    
    m_block_storage = block_storage_factory::create(blocks_dir_path, stash_path);
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
    if (addr != nullptr){
        mmap_flags |= MAP_FIXED;
    }
    m_region_start_address = mmap(addr, m_region_max_capacity, PROT_NONE, mmap_flags, -1, 0);
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
}

sigaction_virtual_memory_manager::~sigaction_virtual_memory_manager() {
    SPDLOG_LOGGER_TRACE(spdlog::default_logger(), "destructor, starting");
    if (close() != 0) {
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "Error in close()");
    }
    SPDLOG_LOGGER_TRACE(spdlog::default_logger(), "destructor, done");
}

void* sigaction_virtual_memory_manager::get_region_start_address() {
    return m_region_start_address;
}

size_t sigaction_virtual_memory_manager::current_region_capacity() {
    return m_region_max_capacity;
}

size_t sigaction_virtual_memory_manager::get_block_size() {
    return m_block_size;
}

void sigaction_virtual_memory_manager::msync() {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), 
        "sigaction_virtual_memory_manager: msync() - start");
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: msync() - Msync Write Dirty LRU");
    // TODO: Implement full msync logic from original
    // This is a placeholder
    std::vector<uint64_t> dirty_lru_vector(dirty_lru.begin(), dirty_lru.end());
    run_parallel_for_count(dirty_lru_vector.size(), [&](size_t index) {
      void* block_address = (void*) dirty_lru_vector[index];
        // if (stash_set.find((uint64_t) block_address) == stash_set.end()){
        uint64_t block_index = ((uint64_t) block_address - (uint64_t) m_region_start_address) / m_block_size;
        bool write_block_fd = true;
        std::string block_hash = m_block_storage->store_block(block_address, write_block_fd, block_index);
        if (block_hash.empty()){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error storing block with index {}", block_index);
        exit(-1);
        }

        blocks_ids[block_index] = block_hash;// std::string(block_storage_local.get_block_hash(block_fd));
        // Change mprotect to read_only
        int mprotect_stat = mprotect(block_address, m_block_size, PROT_READ);
        if (mprotect_stat == -1){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: mprotect error for block with address: {} - {}", (uint64_t) block_address, strerror(errno));
        }
        {
          std::lock_guard<std::mutex> lock(sig_handler_mutex);
          clean_lru.push_front((uint64_t)block_address);
        }
        // }
      });
    dirty_lru.clear();

    SPDLOG_LOGGER_INFO(spdlog::default_logger(), "virtual_memory_manager: msync() - Msync Commit Stashed Blocks");
    std::vector<uint64_t> stash_vector(stash_set.begin(), stash_set.end());

      run_parallel_for_count(stash_vector.size(), [&](size_t index) {
        // block_storage block_storage_local(*m_block_storage);
        void* block_address = (void*) stash_vector[index];
        uint64_t block_index = ((uint64_t) block_address - (uint64_t) m_region_start_address) / m_block_size;
        {
          std::lock_guard<std::mutex> lock(sig_handler_mutex);
            std::string block_hash = /* block_storage_local.*/ m_block_storage->commit_stash_block(block_index);
            if (block_hash.empty()){
            SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error committing stash block with address: {} - {}", (uint64_t) block_address, strerror(errno));
            exit(-1);
            }
            blocks_ids[block_index] = block_hash;
        }
      });
    stash_set.clear();
    update_metadata();
    
    
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), 
        "sigaction_virtual_memory_manager: msync() - done");
        
}

bool sigaction_virtual_memory_manager::snapshot(const char* version_metadata_path) {
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

int sigaction_virtual_memory_manager::close() {
    msync();

  for (auto it = present_blocks.begin(); it != present_blocks.end(); ++it) {
    void* address = (void*)*it;
    int status = munmap(address, m_block_size);
    if (status == -1) {
      SPDLOG_LOGGER_ERROR(spdlog::default_logger(),
        "virtual_memory_manager: Error unmapping region with address {} - {}",
        *it, strerror(errno));
      return -1;
    }
  }

    delete [] blocks_ids;
    delete m_block_storage;
    m_region_start_address = nullptr;
    return 0;
}

void sigaction_virtual_memory_manager::handler(int sig, siginfo_t* si, void* ctx_void_ptr) {
    SPDLOG_LOGGER_TRACE(spdlog::default_logger(), "SIGSEGV handler called");
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

void sigaction_virtual_memory_manager::update_metadata(int sub_region_index) {
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), 
        "sigaction_virtual_memory_manager: update_metadata()");
    
    if (present_blocks.size() == 0) {
        return;
    }
    
    size_t max_address = *present_blocks.rbegin();
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
    if (::close(metadata_fd) == -1){
        SPDLOG_LOGGER_ERROR(spdlog::default_logger(), "virtual_memory_manager: Error closing metadata file after update - {}", strerror(errno));
        exit(-1);
    }
    delete [] blocks_bytes;
          
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), 
        "sigaction_virtual_memory_manager: update_metadata() - done");
}

void sigaction_virtual_memory_manager::evict_if_needed() {
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
