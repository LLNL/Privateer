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
              << " <blocks_path> <versions_base_path> <size in bytes (int)> <update ratio (1 to 100)> <num_iterations> <num_threads>" << std::endl;
    return -1;
  }

  char* blocks_path = argv[1];
  char* versions_base_path = argv[2];
  size_t size_bytes = size_t(atol(argv[3]));
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

  std::string version_0_path = std::string(versions_base_path) + "/version_init";
  Privateer priv(blocks_path, version_0_path.c_str(), size_bytes);

  size_t* data = (size_t*)priv.data();
  size_t num_ints = size_bytes / sizeof(size_t);


  // Randomly and sparsely (1%) fill half array
  float initial_fill_ratio = 0.01;
  size_t initial_fill_size = num_ints*initial_fill_ratio;
  float initial_sparsity = 0.01;
  size_t num_updates = initial_fill_size*initial_sparsity;

  std::cout << "initial_fill_ratio: " << initial_fill_ratio << std::endl;
  std::cout << "initial_fill_size: "  << initial_fill_size  << std::endl;
  std::cout << "initial_sparsity: "   << initial_sparsity   << std::endl;
  std::cout << "num_updates: "        << num_updates        << std::endl;


  std::vector<size_t> random_indices_first_half = get_random_offsets(0, initial_fill_size, num_updates);
  std::vector<size_t>::iterator offset_iterator;

  double initial_fill_start_time = omp_get_wtime();
  #pragma omp parallel for
  for (offset_iterator = random_indices_first_half.begin(); offset_iterator <= random_indices_first_half.end(); ++offset_iterator){
      data[*offset_iterator] += 1;
  }
  double initial_fill_time = omp_get_wtime() - initial_fill_start_time;
  std::cout << "Initial fill time: " << initial_fill_time << " (s)" << std::endl;

  double initial_fill_msync_start_time = omp_get_wtime();
  priv.msync();
  double initial_fill_msync_time = omp_get_wtime() - initial_fill_msync_start_time;
  std::cout << "Initial fill msync time: " << initial_fill_msync_time << " (s)" << std::endl;

  // Incremental updates and snapshots
  size_t update_size = num_ints*(update_ratio*1.0/100);
  std::cout << "update_size: "   << update_size << std::endl;
  for (int i = 0; i < num_iterations; i++){
    std::cout << "------------------------------------------------" << std::endl;
    size_t update_start = initial_fill_size + i*update_size;
    num_updates = update_size*initial_sparsity;

    std::cout << "update_start: "   << update_start   << std::endl;
    std::cout << "num_updates: "    << num_updates    << std::endl;

    std::vector<size_t> random_indices = get_random_offsets(update_start, update_start + update_size, num_updates);
    double iteration_update_start_time = omp_get_wtime();
    #pragma omp parallel for
    for (offset_iterator = random_indices.begin(); offset_iterator < random_indices.end(); ++offset_iterator){
      // std::cout << "updating index: " << (size_t)*offset_iterator << std::endl;
      data[*offset_iterator] += 1;
    }
    double iteration_update_time = omp_get_wtime() - iteration_update_start_time;
    std::cout << "Iteration: " << i << " update time: " << iteration_update_time << " (s)" <<std::endl;

    double snapshot_start_time = omp_get_wtime();
    std::string snapshot_path = std::string(versions_base_path) + "/version_" + std::to_string(i+1);
    if (!priv.snapshot(snapshot_path.c_str())){
      std::cerr << "Error: Snapshot failed for version: " + std::to_string(i+1);
      exit(-1);
    }
    double snapshot_time = omp_get_wtime() - snapshot_start_time;
    std::cout << "Iteration: " << i << " snapshot time: " << snapshot_time << " (s)" <<std::endl;
  }

  return 0;

}
