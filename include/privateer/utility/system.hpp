// Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
// See the top-level LICENSE file for details.
//
// SPDX-License-Identifier: MIT

#pragma once

#include <iostream>
#include <cstdlib>
#include <cmath>

namespace utility{
  inline size_t get_environment_variable(std::string variable_name){
    size_t value;
    char* value_c_str = std::getenv(variable_name.c_str());
    if (value_c_str == NULL){
      value = 0;
    }
    else{
      try{
        value = std::stoi(std::string(value_c_str));
      }
      catch (const std::invalid_argument& ia){
        value = (size_t) NAN;
      }
    }
    return value;
  }

  inline size_t get_available_memory(){ // Taken from: https://github.com/LLNL/umap/blob/develop/src/umap/Buffer.cpp#L269
    uint64_t mem_avail_kb = 0;
    unsigned long mem;
    std::string token;
    std::ifstream file("/proc/meminfo");
    while (file >> token) {
      if (token == "MemAvailable:") {
        if (file >> mem) {
          mem_avail_kb = mem;
        } else {
          std::cerr << "SystemUtil: Error retreivng available memory" << std::endl;
        }
      }
      // ignore rest of the line
      file.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    const uint64_t mem_margin_kb = 16777216;
    mem_avail_kb = (mem_avail_kb > mem_margin_kb) ?(mem_avail_kb-mem_margin_kb) : 0;
    return mem_avail_kb * 1024;
  }

}

