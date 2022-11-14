#pragma once 

#include <inttypes.h>
#include <sys/types.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

#include "../virtual_memory_manager.hpp"
#include "fault_event.hpp"

namespace utility{
  class UFFD{
    public: 
      static void init_uffd();
      static void stop_uffd();
      static void register_uffd_region(uint64_t start, uint64_t length, bool read_only, virtual_memory_manager *vmm);
      static void unregister_uffd_region(uint64_t start, uint64_t length, virtual_memory_manager *vmm);
    private:
      static long m_uffd;
      static pthread_t listener_thread;
      static std::mutex init_mutex, register_mutex, unregister_mutex, stop_mutex;
      static std::map<uint64_t,uint64_t> regions;
      static std::map<uint64_t,virtual_memory_manager*> region_managers;
      static int uffd_pipe[2];
      static void* handler(void* arg);
      static void search_and_dispatch_vmm(utility::fault_event fevent);
      static std::atomic<int> num_handlers;
  };

  long UFFD::m_uffd = -1;
  std::mutex UFFD::init_mutex, UFFD::register_mutex, UFFD::unregister_mutex, UFFD::stop_mutex;
  std::map<uint64_t,uint64_t> UFFD::regions;
  std::map<uint64_t,virtual_memory_manager*> UFFD::region_managers;
  int UFFD::uffd_pipe[2];
  pthread_t UFFD::listener_thread;
  std::atomic<int> UFFD::num_handlers = 0;

  void UFFD::init_uffd(){
    if (m_uffd == -1){
      // printf("Waiting on UFFD::init_mutex Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
      const std::lock_guard<std::mutex> lock(init_mutex);
      // printf("Aquired UFFD::init_mutex Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
      if (m_uffd == -1){
        struct uffdio_api uffdio_api;

        /* Create and enable userfaultfd object. */
        m_uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
        if (m_uffd == -1){
            std::cerr << "Error creating UFFD object - " << strerror(errno) << std::endl;
            exit(-1);
        }
        
        uffdio_api.api = UFFD_API;
        uffdio_api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP;
        if (ioctl(m_uffd, UFFDIO_API, &uffdio_api) == -1){
            std::cerr << "Error ioctl-UFFDIO_API - " << strerror(errno) << std::endl;
            exit(-1);
        }
        if ( !(uffdio_api.features & UFFD_FEATURE_PAGEFAULT_FLAG_WP) ){
          std::cerr << "Error - UFFDIO WP not supported" << std::endl;
          exit(-1);
        }
        // Init pipe
        if (pipe2(uffd_pipe, 0) < 0){
          std::cerr << "Virtual Memory Manager: Error Userfaultfd pipe failed - " << strerror(errno) << std::endl;
          exit(-1);
        }
        // Start listener thread
        int s = pthread_create(&listener_thread, NULL, handler, nullptr);
        // std::cout << "UFFD Thread ID: " << thr << std::endl;
        if (s != 0) {
            errno = s;
            std::cerr << "Error pthread_create - " << strerror(errno) << std::endl;
            exit(-1);
        }
      }
      // printf("Releasing UFFD::init_mutex Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
    }
    num_handlers++;
  }

  void UFFD::stop_uffd(){
    num_handlers--;
    const std::lock_guard<std::mutex> lock(stop_mutex);
    if (num_handlers == 0){
      // printf("THREAD %ld Stopping UFFD\n",(uint64_t) syscall(SYS_gettid));
      char bye[5] = "bye";
      write(uffd_pipe[1], bye, 3);
      int err;
      if((err = pthread_join(listener_thread,NULL)) != 0){
        std::cerr << "Error: Failed to cancel main listener thread - "   << strerror(err) << std::endl;
        exit(-1);
      }
      m_uffd = -1;
    }
  }

  void UFFD::register_uffd_region(uint64_t addr, uint64_t length, bool read_only, virtual_memory_manager *vmm){
    // printf("Waiting on UFFD::register_mutex address %ld length %ld Thread ID: %ld\n", addr , length, (uint64_t) syscall(SYS_gettid));
    const std::lock_guard<std::mutex> lock(register_mutex);
    // printf("Aquired UFFD::register_mutex Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
    if (m_uffd == -1){
      std::cerr << "Error: usefaultfd not initialized using UFFD::init_uffd()\n";
      exit(-1);
    }
    vmm->set_uffd(m_uffd);
    struct uffdio_register uffdio_register;

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = length;
    uffdio_register.mode = /* read_only ? UFFDIO_REGISTER_MODE_MISSING :*/ (UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP);
    if (ioctl(m_uffd, UFFDIO_REGISTER, &uffdio_register) == -1){
        std::cerr << "ioctl-UFFDIO_REGISTER - " << strerror(errno) << std::endl;
        exit(-1);
    }

    if( !(uffdio_register.ioctls & (1 << _UFFDIO_COPY)) || !(uffdio_register.ioctls & (1 << _UFFDIO_WRITEPROTECT))){
      std::cerr << "Error registering UFFD region - Unexpected ioctl set" << std::endl;
      exit(-1);
    }
    regions.insert({addr, length});
    region_managers.insert({addr, vmm});
    // printf("Releasing UFFD::register_mutex Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
  }

  void UFFD::unregister_uffd_region(uint64_t addr, uint64_t length, virtual_memory_manager *vmm){
    // printf("Waiting on UFFD::unregister_mutex Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
    const std::lock_guard<std::mutex> lock(unregister_mutex);
    // printf("Aquired UFFD::unregister_mutex Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
    struct uffdio_range uffdio_range;
    uffdio_range.start = addr;
    uffdio_range.len = length;
    if (ioctl(m_uffd, UFFDIO_UNREGISTER, &uffdio_range) == -1){
      std::cerr << "Error: ioctl-UFFDIO_UNREGISTER - "   << strerror(errno) << std::endl;
      exit(-1);
    }
    region_managers.erase(addr);
    // printf("Releasing UFFD::unregister_mutex Thread ID: %ld\n", (uint64_t) syscall(SYS_gettid));
    vmm->deactivate_uffd_thread();
    /* int err;
    if (fault_handler_thread_pool.find(addr) == fault_handler_thread_pool.end()){
      std::cerr << "Error: Region has not been registered\n";
      exit(-1);
    }
    pthread_t thr = fault_handler_thread_pool[addr];
    if((err = pthread_join(thr,NULL)) != 0){
      std::cerr << "Error: Failed to cancel fault handling thread - "   << strerror(err) << std::endl;
      exit(-1);
    } */
    // std::cout << "AFTER pthread_join" << std::endl;
  }

  void* UFFD::handler(void* arg){
    static struct uffd_msg msg;   /* Data read from userfaultfd */
    static int fault_cnt = 0;     /* Number of faults so far handled */
    /* struct uffdio_copy uffdio_copy;
    struct uffdio_zeropage uffdio_zeropage; */
    ssize_t nread;
    
    // Get UFFD information
      struct pollfd pollfd[3] = {
          { .fd = m_uffd, .events = POLLIN }
        , { .fd = uffd_pipe[0], .events = POLLIN }
        , { .fd = uffd_pipe[1], .events = POLLIN }
      };
      int nready;
    // END: UFFD variables
    // -------------------

    // START: Poll for page fault events
    while (true){
      // printf("POLLING FROM %ld\n", (uint64_t) syscall(SYS_gettid)); // std::cout << "POLLING!!!" << std::endl;
      nready = poll(&pollfd[0], 3, -1);
      if (nready == -1){
        std::cerr << "Error polling UFFD event - " << strerror(errno) << std::endl;
        exit(-1);
      }

      if (pollfd[1].revents & POLLIN || pollfd[2].revents & POLLIN){
        // printf("THREAD %ld Quitting\n",(uint64_t) syscall(SYS_gettid));
        // std::cout << "POLL RECEIVED INTERNAL SIGNAL, Quitting, Bye :)" << std::endl;
        break;
      }

      nread = read(m_uffd, &msg, sizeof(msg));
      if (nread == 0) {
          std::cerr << "EOF on userfaultfd!" << std::endl;
          exit(EXIT_FAILURE);
      }

      if (nread == -1){
        std::cerr << "Error reading UFFD file" << strerror(errno) << std::endl;
        exit(-1);
      }

      /* We expect only one kind of event; verify that assumption. */

      if (msg.event != UFFD_EVENT_PAGEFAULT) {
          std::cerr << "Unexpected event on userfaultfd" << std::endl;
          exit(EXIT_FAILURE);
      }
      uint64_t fault_address = (uint64_t) (msg.arg.pagefault.address);
      bool is_wp_fault = (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP);
      bool is_write_fault = ((!is_wp_fault) && (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE));
      utility::fault_event fevent;
      fevent.address = fault_address;
      fevent.is_wp_fault = is_wp_fault;
      fevent.is_write_fault = is_wp_fault;
      search_and_dispatch_vmm(fevent);
    }
    return NULL;
  }

  void UFFD::search_and_dispatch_vmm(utility::fault_event fevent){
    uint64_t fault_address = fevent.address;
    for (std::map<uint64_t,uint64_t>::iterator it = regions.begin(); it != regions.end(); ++it){
      uint64_t region_addr = it->first;
      uint64_t region_length = it->second;
      if (fault_address >= region_addr && fault_address < (region_addr + region_length)){
        virtual_memory_manager *vmm = region_managers[region_addr];
        vmm->add_page_fault_event(fevent);
        return;
      }
    }
    // printf("Address %ld not found for Thread ID: %ld\n", fault_address , (uint64_t) syscall(SYS_gettid));
    std::cerr << "UFFD Error: Region not registered\n";
    exit(-1);
  }
}