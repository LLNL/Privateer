// Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
// See the top-level LICENSE file for details.
//
// SPDX-License-Identifier: MIT

#pragma once

#include <openssl/sha.h>
#include <sstream>

namespace utility{

  inline std::string compute_hash(char* content_start, size_t content_length){
    unsigned char* msg = (unsigned char*) content_start;
    unsigned char output[32];
    SHA256(msg, content_length, output);
    std::stringstream output_string_stream;
    for (int i = 0; i < 32; i++){
      output_string_stream << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned int) output[i]);
    }
    std::string out_string = output_string_stream.str();
    return out_string;
  }
}

