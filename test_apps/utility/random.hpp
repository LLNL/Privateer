// Copyright 2021 Lawrence Livermore National Security, LLC and other Privateer Project Developers.
// See the top-level LICENSE file for details.
//
// SPDX-License-Identifier: MIT

// Refer to: https://www.fluentcpp.com/2019/05/24/how-to-fill-a-cpp-collection-with-random-values/

#pragma once

#include <algorithm>
#include <iostream>
#include <random>
#include <vector>

namespace utility{
	class RandomNumberBetween
	{
	public:
	    RandomNumberBetween(size_t low, size_t high)
	    : random_engine_{std::random_device{}()}
	    , distribution_{low, high}
	    {
	    }
	    size_t operator()()
	    {
	        return distribution_(random_engine_);
	    }
	private:
	    std::mt19937 random_engine_;
	    std::uniform_int_distribution<size_t> distribution_;
	};
}
