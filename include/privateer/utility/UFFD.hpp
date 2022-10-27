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

namespace utility{
  class UFFD{
    public:
      static void set_virtual_memory_manager(virtual_memory_manager* _vmm){vmm = _vmm;}
      static void* handler(void *uffd_arg){return vmm->handler(uffd_arg);}
      static int init_uffd();
      static void register_uffd_region(uint64_t start, uint64_t length, void* (*fault_handler)(void*), bool read_only, int uffd);
      static void unregister_uffd_region(uint64_t start, uint64_t length, int uffd);
    private:
      static virtual_memory_manager* vmm;
      static long m_uffd;
      static pthread_t thr;
  };

  virtual_memory_manager* UFFD::vmm; 
  long UFFD::m_uffd = -1;
  pthread_t UFFD::thr;

  int UFFD::init_uffd(){
    struct uffdio_api uffdio_api;

    /* Create and enable userfaultfd object. */
    long uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1){
        std::cerr << "Error creating UFFD object - " << strerror(errno) << std::endl;
        exit(-1);
    }
    
    uffdio_api.api = UFFD_API;
    uffdio_api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1){
        std::cerr << "Error ioctl-UFFDIO_API - " << strerror(errno) << std::endl;
        exit(-1);
    }
    if ( !(uffdio_api.features & UFFD_FEATURE_PAGEFAULT_FLAG_WP) ){
      std::cerr << "Error - UFFDIO WP not supported" << std::endl;
      exit(-1);
    }
    return uffd;
  }

  void UFFD::register_uffd_region(uint64_t addr, uint64_t length, void* (*fault_handler)(void*), bool read_only, int uffd){
    std::cout << "UFFD Registering address: " << addr << std::endl;
    std::cout << "UFFD Regiatering length: " << length << std::endl;
    /* if(m_uffd == -1){
      init_uffd();
    } */
    struct uffdio_register uffdio_register;
    int s;

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = length;
    uffdio_register.mode = /* read_only ? UFFDIO_REGISTER_MODE_MISSING :*/ (UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP);
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1){
        std::cerr << "ioctl-UFFDIO_REGISTER - " << strerror(errno) << std::endl;
        exit(-1);
    }

    if( !(uffdio_register.ioctls & (1 << _UFFDIO_COPY)) || !(uffdio_register.ioctls & (1 << _UFFDIO_WRITEPROTECT))){
      std::cerr << "Error registering UFFD region - Unexpected ioctl set" << std::endl;
      exit(-1);
    }

    /* Create a thread that will process the userfaultfd events. */
    s = pthread_create(&thr, NULL, fault_handler, (void*) uffd);
    std::cout << "UFFD Thread ID: " << thr << std::endl;
    if (s != 0) {
        errno = s;
        std::cerr << "Error pthread_create - " << strerror(errno) << std::endl;
        exit(-1);
    }
  }

  void UFFD::unregister_uffd_region(uint64_t addr, uint64_t length, int uffd){
    struct uffdio_range uffdio_range;
    uffdio_range.start = addr;
    uffdio_range.len = length;
    if (ioctl(uffd, UFFDIO_UNREGISTER, &uffdio_range) == -1){
      std::cerr << "Error: ioctl-UFFDIO_UNREGISTER - "   << strerror(errno) << std::endl;
      exit(-1);
    }
    vmm->deactivate_uffd_thread();
    int err;
    std::cout << "BEFORE pthread_join joining ID: " << thr << std::endl;
    if((err = pthread_join(thr,NULL)) != 0){
      std::cerr << "Error: Failed to cancel fault handling thread - "   << strerror(err) << std::endl;
      exit(-1);
    }
    std::cout << "AFTER pthread_join" << std::endl;
  }
}