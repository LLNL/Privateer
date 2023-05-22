#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

namespace utility{
    class s3_util{
        public:
            inline static bool copy_file(const char * source, const char * dest){
                std::string cmd = "aws s3 --endpoint-url" + endpoint + " cp " + source + " " + dest;
                return exec(cmd.c_str());
            }
 
            inline static bool exec(const char* cmd) {
                std::array<char, 128> buffer;
                std::string result;
                std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
                if (!pipe) {
                    // throw std::runtime_error("popen() failed!");
                    std::cerr << "S3 copy error" << std::endl;
                    return false;
                }
                while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                    result += buffer.data();
                }
                std::cout << "S3 copy completed - output: " << result << std::endl;
                return true;
            }

            inline static const std::string endpoint = "http://vastcz101-nfs.llnl.gov";
            inline static const std::string bucket = "s3://cz-youssef2";
    };
}