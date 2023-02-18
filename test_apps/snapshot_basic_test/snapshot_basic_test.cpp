// Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
// See the top-level LICENSE file for details.
//
// SPDX-License-Identifier: MIT

#include <fcntl.h>
#include <omp.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cassert>
#include <iostream>
// #include <parallel/algorithm>
#include <sstream>
#include <string>
#include <vector>
#include "../../include/privateer/privateer.hpp"

int main(int argc, char** argv){

  if (argc != 2){
    std::cerr << "Usage: " << argv[0] << " <base_test_dir>" << std::endl;
    return -1;
  }

  std::string base_test_dir(argv[1]);
  size_t size_bytes = 1024*1024*1024LLU;
  omp_set_num_threads(1);
  {
    /* int mkdir_stat = mkdir(base_test_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (mkdir_stat != 0){
      std::cerr << "Error creating directory at: " << base_test_dir << std::endl;
      return -1;
    } */

    // std::string blocks_base_path = base_test_dir + "/test_snapshot_blocks";
    std::string version_0 = "test_snapshot_version_0";
    // std::string stash_path_ver_0 = base_test_dir + "/test_snapshot_version_0_stash";

    Privateer priv(Privateer::CREATE, base_test_dir.c_str());
    // priv(nullptr, blocks_base_path.c_str(), version_0.c_str(), stash_path_ver_0.c_str(),size_bytes);
    // priv.resize(size_bytes);

    size_t* the_ints = (size_t*) priv.create(nullptr, version_0.c_str(), size_bytes); // priv.data();
    size_t num_ints = size_bytes / sizeof(size_t);

    // Initialize to zeros
    for (size_t i = 0; i < num_ints; ++i){
      the_ints[i] = 0;
    }

    priv.msync();

    // Create snapshots
    for (int j = 1; j <= 10; ++j){
      for (size_t k = 1; k < num_ints; k+=2){
        the_ints[k] = the_ints[k] + 1;
      }
      std::string snapsot_version_name = "version_" + std::to_string(j);
      priv.snapshot(snapsot_version_name.c_str());
    }
  }

  // Validate snapshots
  {
    for (int j = 1; j <= 10; ++j){
      std::string snapsot_version_name = "version_" + std::to_string(j);
      // std::string snapshot_stash = base_test_dir + "/version_" + std::to_string(j) + "_stash";
      Privateer priv(Privateer::OPEN, base_test_dir.c_str());
      size_t* the_ints = (size_t*) priv.open_read_only(nullptr, snapsot_version_name.c_str());// priv.data();
      size_t num_ints = size_bytes / sizeof(size_t);
      for (size_t k = 1; k < num_ints; k+=2){
        if (the_ints[k] != j || the_ints[k-1] != 0){
          std::cout << "Failed to validate version: " << j << std::endl;
          break;
        }
      }
    }
  std::cout << "Snapshots validated successfully" << std::endl;
  }
  return 0;

}
