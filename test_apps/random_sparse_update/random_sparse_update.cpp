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
#include "../utility/random.hpp"

std::vector<size_t> get_random_offsets(size_t region_length, size_t num_updates){
  std::vector<size_t> random_offsets;
  std::generate_n(std::back_inserter(random_offsets), num_updates, utility::RandomNumberBetween(0,region_length - 1));
  return random_offsets;
}

int main(int argc, char** argv){
  if (argc != 6) {
    std::cerr << "Usage: " << argv[0]
              << " <filename> <size GB (int)> <num_threads> <num_iterations> <update ratio>" << std::endl;
    return -1;
  }
  char* fname = argv[1];
  uint64_t size_bytes = uint64_t(atoi(argv[2])) * 1024ULL * 1024ULL * 1024ULL;
  int num_threads = atoi(argv[3]);
  int num_iterations = atoi(argv[4]);
  float update_ratio = std::stof(argv[5]);
  if (update_ratio < 0.0f || update_ratio > 1.0f){
    std::cout << "Error: Update ratio must be between 0.0 and 1.0" << std::endl;
    exit(-1);
  }

  omp_set_num_threads(num_threads);

  std::cout << fname << ", " << argv[2] << " GB, " << num_threads
            << " threads,  MULTI_MAP_PRIVATE" << std::endl;

  // Create mmap
  // multi_mmap_private mapper(std::string(fname), size_bytes);
  // size_t* the_ints = (size_t*)mapper.data();
  std::string blocks_directory_name = std::string(fname) + "_blocks";
  Privateer priv(nullptr, fname, blocks_directory_name.c_str(), size_bytes, size_bytes);
  size_t* data = (size_t*)priv.data();
  size_t num_ints = priv.current_size() / sizeof(size_t); // Is this correct or should we add "get_size()" to privateer and use it here?


  size_t num_updates = (size_t) (num_ints * update_ratio);
  for (int i = 0 ; i < num_iterations ; i++){
    double update_start_time = omp_get_wtime();
    std::vector<size_t> offsets = get_random_offsets(num_ints, num_updates);
    std::vector<size_t>::iterator offset_iterator;
    #pragma omp for // default(none) private(offsets,data)
    for (offset_iterator = offsets.begin(); offset_iterator <= offsets.end(); ++offset_iterator){
      data[*offset_iterator] += 1;
    }
    double update_end_time = omp_get_wtime();
    std::cout << "Update time: " << (update_end_time - update_start_time) << std::endl;

    // double msync_start_time = omp_get_wtime();
    priv.msync();
    // double msync_end_time = omp_get_wtime();
    // std::cout << "msync time: " << (msync_end_time - msync_start_time) << std::endl;
  }


}
