# Privateer

Privateer is a general-purpose data store that optimizes the tradeoff between storage space utilization and I/O performance. 
Privateer uses memory-mapped I/O with private mapping and an optimized writeback mechanism to maximize write parallelism and 
eliminate redundant writes; it also uses content-addressable storage to optimize storage space via de-duplication.

# Getting Started

Privateer consists of header files that are included under privateer/include/privateer/.

## Requirements

* GCC 8.3 or higher with openmp enabled.

* Boost (Tested with 1.77.0).

## Building Privateer

* To build an application that uses Privateer, add the Privateer headers path to the include path using "-I" compliler option or CPLUS_INCLUDE_PATH.

* To build Privateer as a shared library:
```bash
git clone git@github.com:LLNL/Privateer.git
cd Privateer
mkdir build && cd build
cmake -DZSTD_ROOT=<path_to_zstd> -DBOOST_ROOT=<path_to_boost> -DCMAKE_INSTALL_PREFIX=. ..
```

## Building and Running Test Examples

```bash
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=. ..
make install
cd build/test_apps
./<app_name>/<app_executable> <app_args>
```

## Using Privateer

### Including Privateer

```cpp
#include<privateer.hpp>
```

### Creating and memory-mapping a new data store
```cpp
  Privateer privateer(addr, blocks_dir_path, version_metadata_path, max_capacity);
  void* data = privateer.data();
```

### Opening and memory-mapping an existing data store
```cpp
  Privateer privateer(addr, blocks_dir_path, version_metadata_path);
  void*	data = privateer.data();
```

### Writeback
```cpp
  privateer.msync();
```

# Contact

* Karim Youssef (karimy at vt dot edu)
* Keita Iwabuchi (kiwabuchi at llnl dot gov)
* Roger A Pearce (rpearce at llnl dot gov)

# License

Privateer is distributed under the terms of the MIT license.

SPDX-License-Identifier: MIT

# Release

LLNL-CODE-827155
