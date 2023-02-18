// Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
// See the top-level LICENSE file for details.
//
// SPDX-License-Identifier: MIT

#pragma once

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <filesystem>
#include <sys/stat.h>

namespace utility{

  namespace fs = std::filesystem;

  inline bool create_directory(const char *dir_path){
    std::error_code ec;
    if(!fs::create_directory(dir_path, ec)){
      if(!ec){
        return true;
      }
      else{
        std::cerr << "Privateer: Error creating directory: " << dir_path << " - " << ec.message() << std::endl;
        return false;
      }
    }
    return true;
  }

  inline bool directory_exists(const char *dir_path){
    return fs::is_directory(dir_path);
  }

  inline bool file_exists(const char* file_path){
    struct stat buf;
    return (stat(file_path, &buf) == 0);
  }

  inline bool copy_file(const char* source, const char* destination, bool update_existing){
    std::error_code ec;
    if (update_existing){
      fs::copy(source, destination, fs::copy_options::overwrite_existing, ec);
    }
    else{
      fs::copy(source, destination, ec);
    }
    if (ec){
      std::cerr << "Privateer: Error copying file: " << ec.message() << std::endl;
      return false;
    }
    return true;
  }

  inline size_t get_file_size(const char* file_path){
    return fs::file_size(std::string(file_path));
  }

}
