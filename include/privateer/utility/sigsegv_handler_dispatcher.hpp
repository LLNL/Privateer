#include <signal.h>

#include "../virtual_memory_manager.hpp"

namespace utility{
  class sigsegv_handler_dispatcher{
    public:
      static void set_virtual_memory_manager(virtual_memory_manager* _vmm){vmm = _vmm;}
      static void handler(int sig, siginfo_t *si, void *ctx_void_ptr){vmm->handler(sig, si, ctx_void_ptr);}
    private:
      static virtual_memory_manager* vmm;
  };
  virtual_memory_manager* sigsegv_handler_dispatcher::vmm;  
}