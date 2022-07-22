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
#include <parallel/algorithm>
#include <sstream>
#include <string>
#include <vector>
#include "../../include/privateer/privateer.hpp"

int main(int argc, char** argv) {
  if (argc != 5) {
    std::cerr << "Usage: " << argv[0]
              << " <filename> <size GB (int)> <num_threads> <no_init (0 or 1)>" << std::endl;
    return -1;
  }
  char* fname = argv[1];
  uint64_t size_bytes = uint64_t(atoi(argv[2])) * 1024ULL * 1024ULL * 1024ULL;
  int num_threads = atoi(argv[3]);
  int no_init = atoi(argv[4]);

  omp_set_num_threads(num_threads);

  std::cout << fname << ", " << argv[2] << " GB, " << num_threads
            << " threads,  MULTI_MAP_PRIVATE" << std::endl;

  //
  // Create mmap
  // multi_mmap_private mapper(std::string(fname), size_bytes);
  // size_t* the_ints = (size_t*)mapper.data();
  Privateer *priv;
  std::string version_metadata_path = "version_0";
  std::string new_version_metadata_path = "version_1";
  size_t* the_ints;
  if(no_init == 0){
    // std::string blocks_dir_path = std::string(fname) + "_blocks";
    priv = new Privateer(Privateer::CREATE, fname);
    the_ints = (size_t*) priv->create(nullptr, version_metadata_path.c_str(), size_bytes);
  }
  else{
    priv = new Privateer(Privateer::OPEN, fname);
    the_ints = (size_t*) priv->open_immutable(nullptr, version_metadata_path.c_str(), new_version_metadata_path.c_str());
  }
  // size_t* the_ints = (size_t*)priv->data();
  size_t current_size = size_bytes; // priv->current_size();
  size_t num_ints = size_bytes / sizeof(size_t); // Is this correct or should we add "get_size()" to privateer and use it here?

  std::cout << "Current size = " << current_size << std::endl;
  std::cout << "num_ints = " << num_ints << std::endl;

  // size_t chunk_size = 16777216;
  if (no_init == 0){
    // Treaded Init
    std::cout << "Initializing..." << std::endl;
    double init_start = omp_get_wtime();
    // #pragma omp parallel for
    for (size_t i = 0; i < num_ints; ++i) {
      the_ints[i] = (num_ints - 1) - i;
      // the_ints[i] = i / chunk_size;
    }
    double init_end = omp_get_wtime();
    std::cout << "Initialization took: " << (init_end - init_start) << std::endl;
    std::cout << "msync..." << std::endl; 
    double init_msync_start = omp_get_wtime();
    priv->msync();
    double init_msync_end = omp_get_wtime();
    std::cout << "msync took: " << (init_msync_end - init_msync_start) << std::endl;

  }

  // Debugging to be removed
  /* else{
    for (size_t i = 0; i < num_ints; ++i){
      assert(the_ints[i] == ((num_ints - 1) - i));
    }
  } */
  //
  // Sort
  double sort_start = omp_get_wtime();
  /* __gnu_parallel::sort(the_ints, the_ints + num_ints, std::less<uint64_t>(),
                       __gnu_parallel::quicksort_tag()); */
  std::sort(the_ints, the_ints + num_ints);
  double sort_end = omp_get_wtime();
  double sort_msync_start = omp_get_wtime();
  priv->msync();
  double sort_msync_end = omp_get_wtime();

  //
  // Validate
  double validate_start = omp_get_wtime();
  // temp
  bool failed = false;
  //end temp

 size_t chunk_size = 4*1024*1024L;
// #pragma omp parallel for
  for (size_t i = 0; i < num_ints; ++i) {
    /* if (i % chunk_size == 0){
      std::cout << "i: " << i << " the_ints[i]: " << the_ints[i] << std::endl;
    } */
    
    if (the_ints[i] != i) {
      std::cerr << "Failed to Validate " << i << " " << the_ints[i] << std::endl;
      exit(-1);
      // std::cout << "i: " << i << "the_ints[i]: " << the_ints[i] << std::endl;
      // failed = true;
    }
    /* if (i % 1048576 == 0){
      std::cout << "block: " << (i / 1048576) << " passed" << std::endl;
    } */
  }
  // std::cout << "Failed: " << failed << std::endl;
  double validate_end = omp_get_wtime();
  /* double validate_msync_start = omp_get_wtime();
  priv->msync();
  double validate_msync_end = omp_get_wtime(); */

  delete priv;
  std::cout << "Sort time:     " << sort_end - sort_start << std::endl
            << "Sort Msync time:     " << sort_msync_end - sort_msync_start
            << std::endl
            << "Validate time: " << validate_end - validate_start << std::endl;
            /* << "Validate Msync time: "
            << validate_msync_end - validate_msync_start << std::endl; */


  return 0;
}
