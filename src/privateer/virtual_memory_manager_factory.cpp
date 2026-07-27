#include <privateer/virtual_memory_manager_factory.hpp>

#ifdef SIGACTION
#include <privateer/sigaction_virtual_memory_manager.hpp>
#endif

#ifdef USERFAULTFD
#include <privateer/uffd_virtual_memory_manager.hpp>
#endif

#include <spdlog/spdlog.h>

virtual_memory_manager_base* virtual_memory_manager_factory::create(
    void* start_address, 
    size_t region_max_capacity,
    size_t block_size, 
    std::string version_metadata_path,
    std::string blocks_path, 
    std::string stash_path,
    bool allow_overwrite) {
    
#ifdef USERFAULTFD
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), 
        "virtual_memory_manager_factory: Creating UFFD virtual memory manager");
    return new uffd_virtual_memory_manager(start_address, region_max_capacity, block_size,
                                          version_metadata_path, blocks_path, stash_path,
                                          allow_overwrite);
#elif defined(SIGACTION)
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), 
        "virtual_memory_manager_factory: Creating SIGACTION virtual memory manager");
    return new sigaction_virtual_memory_manager(start_address, region_max_capacity, block_size,
                                               version_metadata_path, blocks_path, stash_path,
                                               allow_overwrite);
#else
    #error "Either SIGACTION or USERFAULTFD must be defined"
#endif
}

virtual_memory_manager_base* virtual_memory_manager_factory::open(
    void* addr, 
    std::string version_metadata_path,
    std::string stash_path, 
    bool read_only) {
    
#ifdef USERFAULTFD
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), 
        "virtual_memory_manager_factory: Opening UFFD virtual memory manager");
    return new uffd_virtual_memory_manager(addr, version_metadata_path, stash_path, read_only);
#elif defined(SIGACTION)
    SPDLOG_LOGGER_INFO(spdlog::default_logger(), 
        "virtual_memory_manager_factory: Opening SIGACTION virtual memory manager");
    return new sigaction_virtual_memory_manager(addr, version_metadata_path, stash_path, read_only);
#else
    #error "Either SIGACTION or USERFAULTFD must be defined"
#endif
}
