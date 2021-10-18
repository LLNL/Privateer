// Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
// See the top-level LICENSE file for details.
//
// SPDX-License-Identifier: MIT

#pragma once

#include <iostream>
#include <cstdlib>
#include <cmath>

namespace utility{
  size_t get_environment_variable(std::string variable_name){
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
}

#endif
