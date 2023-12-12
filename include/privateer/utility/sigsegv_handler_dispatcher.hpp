#include <signal.h>
#include <mutex>

#include "../virtual_memory_manager.hpp"

namespace utility{
  class sigsegv_handler_dispatcher{
    public:
      inline static void add_virtual_memory_manager(uint64_t addr, uint64_t length, virtual_memory_manager* vmm){
        std::lock_guard<std::mutex> region_manager_add_lock(region_manager_add_mutex);
        regions.insert({addr, length});
        region_managers.insert({addr, vmm});
      }

      inline static void remove_virtual_memory_manager(uint64_t addr){
        std::lock_guard<std::mutex> region_manager_remove_lock(region_manager_remove_mutex);
        regions.erase(addr);
        region_managers.erase(addr);
      }

      inline static void handler(int sig, siginfo_t *si, void *ctx_void_ptr){
        std::lock_guard<std::mutex> region_manager_handler_lock(region_manager_handler_mutex);
        // Get address information
        uint64_t fault_address = (uint64_t) si->si_addr;
        virtual_memory_manager *vmm;

        // Map to VMM
        for (std::map<uint64_t,uint64_t>::iterator it = regions.begin(); it != regions.end(); ++it){
          uint64_t region_addr = it->first;
          uint64_t region_length = it->second;
          // std::cout << "Searching for Address: " << fault_address << std::endl;
          if (fault_address >= region_addr && fault_address < (region_addr + region_length)){
            vmm = region_managers[region_addr];
            vmm->handler(sig, si, ctx_void_ptr);
            return;
          }
        }
        // printf("Address %ld not found for Thread ID: %ld\n", fault_address , (uint64_t) syscall(SYS_gettid));
        std::cerr << "Fault address out of range\n";
        exit(-1);

        // Call VMM->handler on appropriate vmm
        
      }
    private:
      // inline static virtual_memory_manager* vmm;
      inline static std::map<uint64_t,uint64_t> regions;
      inline static std::map<uint64_t,virtual_memory_manager*> region_managers;
      inline static std::mutex region_manager_add_mutex;
      inline static std::mutex region_manager_remove_mutex;
      inline static std::mutex region_manager_handler_mutex;
  };
  // virtual_memory_manager* sigsegv_handler_dispatcher::vmm;  
}
