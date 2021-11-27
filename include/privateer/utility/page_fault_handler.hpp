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
#include <sys/time.h>
#include <stdio.h>

namespace utility{

  class PageFaultHandler {
    public:
      PageFaultHandler(size_t page_size, uint64_t max_mem_usage, std::string *backing_store_blocks_ids);
      void add_mapping(uint64_t start, size_t length);
    private:
      size_t page_size;
      uint64_t max_mem_usage;
      static std::list<uint64_t> clean_lru;
      static std::list<uint64_t> dirty_lru;
      std::string *blocks_ids;
      void handler(int sig, siginfo_t *si, void *unused);
      void evict();
  };

  PageFaultHandler::PageFaultHandler(uint64_t page_size, uint64_t max_mem_usage){
    this.page_size = page_size;
    this.max_mem_usage = max_mem_usage;

    // Define the signal and associate with handler
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
      std::cerr << "Error: sigaction failed" << std::endl;
  }

}
