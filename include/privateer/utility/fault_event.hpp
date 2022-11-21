#pragma once

namespace utility{
    struct fault_event{
        uint64_t address;
        bool is_wp_fault;
        bool is_write_fault;
        bool operator==(const fault_event& rhs) const{
            return (address == rhs.address && is_wp_fault == rhs.is_wp_fault && is_write_fault == rhs.is_write_fault);
        }

        bool operator<(const fault_event& rhs) const{
            return (address < rhs.address);
        }

        /* bool operator>(const fault_event& rhs){
            return (address > rhs.address);
        }

        bool operator<=(const fault_event& rhs){
            return (address <= rhs.address);
        }

        bool operator>=(const fault_event& rhs){
            return (address >= rhs.address);
        } */
    };
}