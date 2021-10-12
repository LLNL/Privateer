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


int main(int argc, char** argv){

  if (argc != 2){
    std::cerr << "Usage: " << argv[0] << " <output_file_name>" << std::endl;
    return -1;
  }

  size_t size_bytes = (size_t) 255*1024*1024*1024;
  std::string base_path(argv[1]);
  Privateer priv((base_path + "_blocks").c_str() , base_path.c_str(), size_bytes);
  size_t* data = (size_t*)priv.data();
  size_t num_ints = priv.current_size() / sizeof(size_t);
  
  size_t start = 0;
  size_t middle = num_ints / 2;
  size_t middle_to_end = ( num_ints / 2 ) + ( num_ints / 4 );
  size_t end = num_ints - 1;
  
  data[start] = 1;
  std::cout << "written to: " << start << std::endl;
  data[middle] = 1;
  std::cout << "written to: " << middle << std::endl;
  data[middle_to_end] = 1;
  std::cout << "written to: " << middle_to_end << std::endl;
  data[end] = 1;
  std::cout << "written to: " << end << std::endl;
}
