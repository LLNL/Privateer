// Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
// See the top-level LICENSE file for details.
//
// SPDX-License-Identifier: MIT

#include <fcntl.h>
#include <omp.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <cassert>
#include <iostream>
// #include <parallel/algorithm>
#include <sstream>
#include <string>
#include <vector>
#include "../../include/privateer/privateer.hpp"

int main(int argc, char** argv) {
  if (argc != 4) {
    std::cerr << "Usage: " << argv[0]
              << " <filename> <size GB (int)> <num_threads>" << std::endl;
    return -1;
  }
  char* fname = argv[1];
  uint64_t size_bytes = uint64_t(atoi(argv[2])) * 1024ULL * 1024ULL * 1024ULL;
  int num_threads = atoi(argv[3]);

  omp_set_num_threads(num_threads);

  std::cout << fname << ", " << argv[2] << " GB, " << num_threads
            << " threads,  MULTI_MAP_PRIVATE" << std::endl;

  //
  // Create mmap
  // multi_mmap_private mapper(std::string(fname), size_bytes);
  // size_t* the_ints = (size_t*)mapper.data();
  std::string stash_path = std::string(fname) + "_stash_init";
  std::string blocks_path = std::string(fname) + "_blocks";
  std::string image_name = "version_0";
  Privateer* priv = new Privateer(Privateer::CREATE, fname);
  size_t* the_ints = (size_t*) priv->create(nullptr, image_name.c_str(), size_bytes);
  size_t num_ints = size_bytes / sizeof(size_t); // Is this correct or should we add "get_size()" to privateer and use it here?



  // Treaded Init
  std::cout << "Initializing..." << std::endl;
  double init_start = omp_get_wtime();

  // size_t chunk_size = 16777216;
  // Treaded Init
  // #pragma omp parallel for
  for (size_t i = 0; i < num_ints; ++i) {
    the_ints[i] = (num_ints - 1) - i;
    // the_ints[i] = ((num_ints - 1)/chunk_size) - (i / chunk_size);
    /* if(i % chunk_size == 0){
      std::cout << the_ints[i] << std::endl; // at 0, chunk_size, 2xchun_size,...
    } */
  }

  double init_end = omp_get_wtime();
  std::cout << "Initialization done" << std::endl;
  std::cout << "msync..." << std::endl;
  double init_msync_start = omp_get_wtime();
  priv->msync();
  double init_msync_end = omp_get_wtime();
  std::cout << "msync done" << std::endl;
  //
  std::cout << "Init Time:     " << init_end - init_start << std::endl
            << "Init Msync Time:     " << init_msync_end - init_msync_start
            << std::endl;
  delete priv;
  // debug: validate
  /* for (size_t i = 0; i < num_ints; ++i){
    assert(the_ints[i] == ((num_ints - 1) - i));
  } */

  return 0;
}
