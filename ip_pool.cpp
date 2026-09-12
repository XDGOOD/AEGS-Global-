#include "ip_pool.h"
#include <stdexcept>
#include <vector>
#include <sstream>
#include <cstdio>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

IpPool::IpPool(const std::string& network_cidr) {
    size_t slash_pos = network_cidr.find('/');
    if (slash_pos == std::string::npos) {
        throw std::invalid_argument("Invalid CIDR format");
    }

    std::string ip_str = network_cidr.substr(0, slash_pos);
    int prefix = 0;
    try {
        prefix = std::stoi(network_cidr.substr(slash_pos + 1));
    } catch (...) {
        throw std::invalid_argument("Invalid CIDR prefix");
    }
    if (prefix < 16 || prefix > 30) {
        throw std::invalid_argument("CIDR prefix must be between /16 and /30 for VPN IP pool");
    }

    uint32_t ip;
#ifdef _WIN32
    if (inet_pton(AF_INET, ip_str.c_str(), &ip) != 1) {
        throw std::invalid_argument("Invalid IP address format");
    }
    ip = ntohl(ip);
#else
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        throw std::invalid_argument("Invalid IP address format");
    }
    ip = ntohl(addr.s_addr);
#endif

    uint32_t mask = (prefix == 32) ? 0xFFFFFFFFu : (~0u << (32 - prefix));
    net_base_ = ip & mask;
    net_mask_ = mask;

    uint32_t num_ips = (1ULL << (32 - prefix));
    
    // Fill queue, skipping .0 (network) and .1 (server reserved), and broadcast
    total_ = 0;
    if (num_ips > 3) {
        for (uint32_t i = 2; i < num_ips - 1; ++i) {
            free_ips_.push(net_base_ + i);
            total_++;
        }
    }
}

std::optional<uint32_t> IpPool::allocate() {
    std::lock_guard<std::mutex> lock(mu_);
    if (free_ips_.empty()) {
        return std::nullopt;
    }
    uint32_t ip = free_ips_.front();
    free_ips_.pop();
    allocated_[ip] = true;
    return ip;
}

void IpPool::release(uint32_t ip_host_order) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = allocated_.find(ip_host_order);
    if (it != allocated_.end() && it->second) {
        it->second = false;
        allocated_.erase(it);
        free_ips_.push(ip_host_order);
    }
}

bool IpPool::contains(uint32_t ip_host_order) const {
    return (ip_host_order & net_mask_) == net_base_;
}

std::string IpPool::to_string(uint32_t ip) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             (ip >> 24) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF,
             ip & 0xFF);
    return std::string(buf);
}

size_t IpPool::available() const {
    std::lock_guard<std::mutex> lock(mu_);
    return free_ips_.size();
}
