#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <queue>
#include <mutex>
#include <optional>

class IpPool {
public:
    // Creates pool from base + prefix, e.g. ("10.8.0.0", 24) -> .2 through .254
    // .1 is reserved for server
    IpPool(const std::string& network_cidr);

    // Allocate next available IP. Returns nullopt if pool exhausted.
    std::optional<uint32_t> allocate();  // returns host byte order IP

    // Release IP back to pool
    void release(uint32_t ip_host_order);

    // Check if IP is in pool range
    bool contains(uint32_t ip_host_order) const;

    // Convert uint32 host-order to dotted notation
    static std::string to_string(uint32_t ip);

    size_t available() const;
    size_t total() const { return total_; }

private:
    uint32_t net_base_;   // host byte order
    uint32_t net_mask_;   // host byte order
    size_t   total_;
    std::queue<uint32_t>          free_ips_;
    std::unordered_map<uint32_t, bool> allocated_;
    mutable std::mutex mu_;
};
