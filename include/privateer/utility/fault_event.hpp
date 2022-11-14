#pragma once

namespace utility{
    struct fault_event{
        uint64_t address;
        bool is_wp_fault;
        bool is_write_fault;
    };
}