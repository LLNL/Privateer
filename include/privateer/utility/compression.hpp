#pragma once
#include <iostream>
#include <algorithm>
#include <string>

#include <stdlib.h>    // free
#include "zstd.h"

/* #include <sstream>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/zstd.hpp> */

namespace utility{
    size_t compress(void* input_buffer, size_t input_buffer_size, void* output_buffer){
        std::cout << "COMPRESSINIG" << std::endl;
        size_t output_buffer_size_bound = ZSTD_compressBound(input_buffer_size);
        size_t output_size = ZSTD_compress(output_buffer, output_buffer_size_bound, input_buffer, input_buffer_size, 1);
        if (ZSTD_isError(output_size)){
            std::cerr << "Compression Error: - " << ZSTD_getErrorName(output_size) << std::endl;
            return -1;
        }
        return output_size;
    }

    size_t decompress(void* input_buffer, void* output_buffer){
        std::cout << "DECOMPRESSING" << std::endl;
        size_t compressed_size;
        // void* const compressed_buffer = mallocAndLoadFile_orDie(file_name, &compressed_size);
        /* Read the content size from the frame header. For simplicity we require
        * that it is always present. By default, zstd will write the content size
        * in the header when it is known. If you can't guarantee that the frame
        * content size is always written into the header, either use streaming
        * decompression, or ZSTD_decompressBound().
        */
        uint64_t rSize = ZSTD_getFrameContentSize(input_buffer, compressed_size);
        if (rSize == ZSTD_CONTENTSIZE_ERROR){
            std::cerr << "Decompression Error: File was not compressed by ZSTD" << std::endl;
            return -1;
        }

        if(rSize == ZSTD_CONTENTSIZE_UNKNOWN){
            std::cerr << "Decompression Error: File unable to get content size" << std::endl;
            return -1;
        }
        

        size_t const output_size = ZSTD_decompress(output_buffer, rSize, input_buffer, compressed_size);
        if (ZSTD_isError(output_size)){
            std::cerr << "Decompression Error: - " << ZSTD_getErrorName(output_size) << std::endl;
            return -1;
        }
        

        // free(compressed_buffer);
    }
}

/* namespace utility{
    std::string compress(char* data){
        namespace bio = boost::iostreams;
        
        std::stringstream compressed;
        std::stringstream origin;
        origin << data; //(data);

        bio::filtering_streambuf<bio::input> out;
        out.push(bio::zstd_compressor(bio::zstd_params(bio::zstd::default_compression)));

        out.push(origin);
        bio::copy(out, compressed);

        return compressed.str();
    }
    
    std::string decompress(char* data){
        namespace bio = boost::iostreams;
        
        std::stringstream decompressed;
        std::stringstream origin;
        origin << data; //(data);

        bio::filtering_streambuf<bio::input> out;
        out.push(bio::zstd_decompressor());

        out.push(origin);
        bio::copy(out, decompressed);

        return decompressed.str();
    } 
} */