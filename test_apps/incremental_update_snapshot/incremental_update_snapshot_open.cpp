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
#include <fstream>
#include <cstdlib>
#include <filesystem>
// #include <parallel/algorithm>
#include <sstream>
#include <string>
#include <vector>

#include "../../include/privateer/privateer.hpp"
#include "../utility/random.hpp"

std::vector<size_t> get_random_offsets(size_t region_start, size_t region_end, size_t num_updates){
  std::vector<size_t> random_offsets;
  std::generate_n(std::back_inserter(random_offsets), num_updates, utility::RandomNumberBetween(region_start,region_end - 1));
  return random_offsets;
}

int main(int argc, char **argv){

  if (argc != 7) {
    std::cerr << "Usage: " << argv[0]
              << " <blocks_path> <version_path> <versions_base_path> <update ratio (1 to 100)> <num_iterations> <num_threads>" << std::endl;
    return -1;
  }

  char* blocks_path = argv[1];
  char* version_path = argv[2];
  char* versions_base_path = argv[3];
  int update_ratio = atoi(argv[4]);
  if (update_ratio < 1 || update_ratio > 100){
    std::cerr << "Error: update ratio must be between 1 and 100" << std::endl;
  }
  int num_iterations = atoi(argv[5]);
  int num_threads = atoi(argv[6]);

  omp_set_num_threads(num_threads);

  // Create versions base path
  std::error_code ec;
  if(!fs::create_directory(versions_base_path)){
    if(ec){
      std::cerr << "Error creating directory - " << strerror(errno) << std::endl;
      exit(-1);
    }
  }

  Privateer priv(version_path, false);

  size_t* data = (size_t*)priv.data();
  size_t num_ints = priv.current_size() / sizeof(size_t);


  float initial_sparsity = 0.01;

  std::cout << "initial_sparsity: "   << initial_sparsity   << std::endl;

  // start from the middle of the region
  size_t starting_index = (priv.current_size()/sizeof(size_t)) / 2;

  // Incremental updates and snapshots
  size_t update_size = num_ints*(update_ratio*1.0/100);
  std::cout << "update_size: "   << update_size << std::endl;
  for (int i = 0; i < num_iterations; i++){
    std::cout << "------------------------------------------------" << std::endl;
    size_t update_start =  starting_index + i*update_size;
    size_t num_updates = update_size*initial_sparsity;

    std::cout << "update_start: "   << update_start   << std::endl;
    std::cout << "num_updates: "    << num_updates    << std::endl;

    std::vector<size_t> random_indices = get_random_offsets(update_start, update_start + update_size, num_updates);
    std::vector<size_t>::iterator offset_iterator;
    #pragma omp parallel for
    for (offset_iterator = random_indices.begin(); offset_iterator < random_indices.end(); ++offset_iterator){
      // std::cout << "updating index: " << (size_t)*offset_iterator << std::endl;
      data[*offset_iterator] += 1;
    }
    std::string snapshot_path = std::string(versions_base_path) + "/version_" + std::to_string(i+1);
    if (!priv.snapshot(snapshot_path.c_str())){
      std::cerr << "Error: Snapshot failed for version: " + std::to_string(i+1);
      exit(-1);
    }
  }

  return 0;

}
