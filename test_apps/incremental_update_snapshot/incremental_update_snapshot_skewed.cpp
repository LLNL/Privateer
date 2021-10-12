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

  if (argc != 9) {
    std::cerr << "Usage: " << argv[0]
              << " <blocks_path> <versions_base_path> <size in bytes (int)>"
              << " <total updates percent (1 to 100)> <dense region size percent (1 100)> <dense region update percent (1 100)>" 
              << " <num_iterations> <num_threads>" 
              << std::endl;
    return -1;
  }

  char* blocks_path = argv[1];
  char* versions_base_path = argv[2];
  size_t size_bytes = size_t(atol(argv[3]));
  int update_ratio = atoi(argv[4]);
  if (update_ratio < 1 || update_ratio > 100){
    std::cerr << "Error: update ratio must be between 1 and 100" << std::endl;
  }
  int dense_region_size_ratio = atoi(argv[5]);
  int dense_region_update_ratio = atoi(argv[6]);
  int num_iterations = atoi(argv[7]);
  int num_threads = atoi(argv[8]);

  omp_set_num_threads(num_threads);

  // Create versions base path
  std::error_code ec;
  if(!fs::create_directory(versions_base_path)){
    if(ec){
      std::cerr << "Error creating directory - " << strerror(errno) << std::endl;
      exit(-1);
    }
  }

  std::string version_0_path = std::string(versions_base_path) + "/version_0";
  Privateer priv(blocks_path, version_0_path.c_str(), size_bytes);

  size_t* data = (size_t*)priv.data();
  size_t num_ints = size_bytes / sizeof(size_t);

  // Initialize to zeros
  #pragma omp parallel for
  for (size_t i = 0; i < num_ints / 2; ++i){

    data[i] = 0;
  }

  priv.msync();

  size_t total_updates_per_iteration = num_ints * (update_ratio*1.0/100);
  size_t dense_region_length = num_ints * (dense_region_size_ratio*1.0/100);
  size_t num_updates_dense_region = total_updates_per_iteration * (dense_region_update_ratio*1.0/100);
  size_t sparse_region_start = dense_region_length;
  size_t num_updates_sparse_region = total_updates_per_iteration - num_updates_dense_region;

  std::cout << "region length (integers): " << num_ints << std::endl;
  std::cout << "total_updates_per_iteration: " << total_updates_per_iteration << std::endl;
  std::cout << "dense_region_length: " << dense_region_length << std::endl;
  std::cout << "num_updates_dense_region: " << num_updates_dense_region << std::endl;
  std::cout << "sparse_region_start: " << sparse_region_start << std::endl;
  std::cout << "num_updates_sparse_region: " << num_updates_sparse_region << std::endl;

  // Incremental updates and snapshots
  for (int i = 0; i < num_iterations; i++){
    std::cout << "Iteration: " << i << std::endl;
    // update dense region
    std::vector<size_t> random_indices = get_random_offsets(0, dense_region_length, num_updates_dense_region);
    std::vector<size_t>::iterator offset_iterator;
    #pragma omp parallel for
    for (offset_iterator = random_indices.begin(); offset_iterator < random_indices.end(); ++offset_iterator){
      data[*offset_iterator] += 1;
    }
    std::cout << "Done updating dense region" << std::endl;
    // update sparse region
    std::vector<size_t> random_indices_sparse_region = get_random_offsets(sparse_region_start, num_ints, num_updates_sparse_region);
    std::vector<size_t>::iterator offset_iterator_sparse_region;

    #pragma omp parallel for
    for (offset_iterator_sparse_region = random_indices_sparse_region.begin(); offset_iterator_sparse_region <= random_indices_sparse_region.end(); offset_iterator_sparse_region++){
      data[*offset_iterator_sparse_region] += 1;
    }
    std::cout << "Done updating sparse region" << std::endl;
    // snapshot
    std::string snapshot_path = std::string(versions_base_path) + "/version_" + std::to_string(i+1);
    if (!priv.snapshot(snapshot_path.c_str())){
      std::cerr << "Error: Snapshot failed for version: " + std::to_string(i+1);
      exit(-1);
    }
  }

  return 0;

}
