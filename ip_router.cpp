// ==============================================================================
// AEGS v3 -- IP Packet Router Implementation
// ==============================================================================
#include "ip_router.h"
#include "tun_interface.h"
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <poll.h>
#include <unistd.h>

static bool cidr_to_net_mask(const std::string& cidr,
                              uint32_t& net, uint32_t& mask, int& prefix) {
    auto slash = cidr.find('/');
    if (slash == std::string::npos) return false;
    std::string ip_s = cidr.substr(0, slash);
    int bits = std::stoi(cidr.substr(slash + 1));
    if (bits < 0 || bits > 32) return false;
    struct in_addr addr{};
    if (inet_pton(AF_INET, ip_s.c_str(), &addr) != 1) return false;
    net    = ntohl(addr.s_addr);
    mask   = bits == 0 ? 0u : (~0u << (32 - bits));
    prefix = bits;
    return true;
}

IpRouter::IpRouter(TunInterface& tun, int mtu) : tun_(tun), mtu_(mtu) {}
IpRouter::~IpRouter() { stop(); }

bool IpRouter::add_route(const std::string& cidr, RouteType type, int metric) {
    RouteEntry e{};
    if (!cidr_to_net_mask(cidr, e.network, e.netmask, e.prefix_len)) {
        fprintf(stderr, "[IpRouter] invalid CIDR: %s\n", cidr.c_str());
        return false;
    }
    e.type   = type;
    e.metric = metric;
    std::lock_guard<std::mutex> lk(routes_mu_);
    routes_.push_back(e);
    std::sort(routes_.begin(), routes_.end(),
        [](const RouteEntry& a, const RouteEntry& b) {
            if (a.metric != b.metric) return a.metric < b.metric;
            return a.prefix_len > b.prefix_len;
        });
    return true;
}

RouteType IpRouter::lookup_route(uint32_t dst) const {
    std::lock_guard<std::mutex> lk(routes_mu_);
    for (const auto& r : routes_)
        if ((dst & r.netmask) == r.network) return r.type;
    return RouteType::BYPASS;
}

bool IpRouter::start() {
    if (running_.exchange(true)) return true;
    reader_thread_ = std::thread(&IpRouter::reader_loop, this);
    return true;
}

void IpRouter::stop() {
    running_.store(false);
    if (reader_thread_.joinable()) reader_thread_.join();
}

void IpRouter::reader_loop() {
    std::vector<uint8_t> buf(mtu_ + 64);
    struct pollfd pfd{ tun_.fd(), POLLIN, 0 };

    while (running_.load(std::memory_order_relaxed)) {
        int ret = poll(&pfd, 1, 100);
        if (ret <= 0) continue;
        if (!(pfd.revents & POLLIN)) continue;

        ssize_t n = tun_.read_packet(buf.data(), buf.size());
        if (n <= 0) continue;

        pkts_recv_.fetch_add(1, std::memory_order_relaxed);
        bytes_recv_.fetch_add((uint64_t)n, std::memory_order_relaxed);

        IPv4Header hdr{};
        if (!parse_ipv4(buf.data(), (size_t)n, hdr)) {
            pkts_drop_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        RouteType rt = lookup_route(hdr.daddr);
        switch (rt) {
        case RouteType::AEGS:
            if (aegs_sender_ && aegs_sender_(buf.data(), (size_t)n)) {
                pkts_sent_.fetch_add(1, std::memory_order_relaxed);
                bytes_sent_.fetch_add((uint64_t)n, std::memory_order_relaxed);
            } else {
                pkts_drop_.fetch_add(1, std::memory_order_relaxed);
            }
            break;
        case RouteType::BYPASS:
        case RouteType::BLOCK:
            pkts_drop_.fetch_add(1, std::memory_order_relaxed);
            break;
        }
    }
}

bool IpRouter::inject_packet(const uint8_t* pkt, size_t len) {
    if (len == 0 || len > (size_t)mtu_ + 64) return false;
    ssize_t w = tun_.write_packet(pkt, len);
    if (w != (ssize_t)len) {
        pkts_drop_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    pkts_recv_.fetch_add(1, std::memory_order_relaxed);
    bytes_recv_.fetch_add(len, std::memory_order_relaxed);
    return true;
}
