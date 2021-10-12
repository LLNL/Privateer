// Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
// See the top-level LICENSE file for details.
//
// SPDX-License-Identifier: MIT

#include <mpi.h>
#include <stdio.h>
#include <iostream>
#include <cassert>

#include "../../include/privateer/privateer.hpp"

int main(int argc, char** argv) {
    std::cout << "Hello" << std::endl;
    // Initialize the MPI environment
    MPI_Init(NULL, NULL);
    std::cout << "Hello MPI" << std::endl;
    // Get the number of processes
    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    // Get the rank of the process
    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);

    // Get the name of the processor
    char processor_name[MPI_MAX_PROCESSOR_NAME];
    int name_len;
    MPI_Get_processor_name(processor_name, &name_len);

    // Print off a hello world message
    // printf("Hello world from processor %s, rank %d out of %d processors\n", processor_name, world_rank, world_size);
    std::string blocks_directory_path = "/l/ssd/test_blocks_repository";
    std::string version_0_metadata_path = "/l/ssd/test_concurrent_version_0";
    std::string version_metadata_prefix = "/l/ssd/test_concurrent_version_";
    size_t region_capacity = 1024*1024*1024;
    if (world_rank == 0){
      std::cout << "Hello Rank zero" << std::endl;
      // Create a Privateer object
      Privateer privateer(blocks_directory_path.c_str(), version_0_metadata_path.c_str(), region_capacity);
      privateer.resize(region_capacity);
      /* size_t * data = (size_t*) privateer.data();
      data[region_capacity / sizeof(size_t) - 1] = 1;
      privateer.msync(); */
      // Broadcast blocks path
      // MPI_Bcast(blocks_directory_path.c_str(), blocks_directory_path.length(), MPI_CHAR, world_rank, MPI_COMM_WORLD);
    }
    // Synchronize
    MPI_Barrier(MPI_COMM_WORLD);
    if (world_rank != 0){
      std::string version_metadata_path = version_metadata_prefix + std::to_string(world_rank);
      Privateer privateer(version_0_metadata_path.c_str(), version_metadata_path.c_str());
      size_t *data = (size_t*) privateer.data();
      size_t values_size = region_capacity / sizeof(size_t);
      // Fill region
      for (size_t i = 0; i < values_size; i++){
        /* if (i % 1024 == 0){
          std::cout << "Filling " << i << std::endl;
        } */
        data[i] = i;
      }
      // Flush
      privateer.msync();
    }
    // Synchronize
    MPI_Barrier(MPI_COMM_WORLD);
    if (world_rank == 0){
      // Validate
      for (int i = 1; i < world_size; i++){
        std::string version_metadata_path = version_metadata_prefix + std::to_string(i);
        bool read_only = true;
        Privateer privateer(version_metadata_path.c_str(), read_only);
        size_t *data = (size_t*) privateer.data();
        size_t values_size = region_capacity / sizeof(size_t);
        // Validate
        for (size_t j = 0; j < values_size; j++){
          assert(data[j] == j);
        }
      }
    }

    // Finalize the MPI environment.
    MPI_Finalize();
    return 0;
}
