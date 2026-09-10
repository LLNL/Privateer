# Build API document, Example, Test, and Utility Programs 

## Requirements

* GCC 8.3 or higher with openmp enabled.

* Boost (Tested with 1.77.0).

* Spdlog (Tested with 1.9.2)

## Building Privateer

* To build an application that uses Privateer, add the Privateer headers path to the include path using "-I" compiler option or CPLUS_INCLUDE_PATH.

* To build Privateer as a shared library:
```bash
git clone git@github.com:LLNL/Privateer.git
cd Privateer
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=. ..
```

## Building and Running Test Examples

```bash
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=. ..
make install
ctest
```


## Additional CMake Options

In addition to the standard CMake options, Metall have additional options as follows:

* BUILD_DOC
    * Build API document using Doxygen
    * One can also build the document by using doxygen directly; see README.md in the repository of Metall.
    * ON or OFF (default is OFF)

* BUILD_C
    * Build a library for C interface
    * ON or OFF (default is OFF).

* ENABLE_COMPRESSION
    * Build using zstd compression algorithm
    * ON or OFF (default is OFF).

* ENABLE_UFFD
    * Build using userfaultfd implementation
    * ON or OFF (default is OFF, using sigaction based implementation).

