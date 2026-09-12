#pragma once
// ==============================================================================
// AEGS v3 — IP Packet Router
// Routes IP packets between the TUN interface (aegs0) and encrypted AEGS sessions
// ==============================================================================
#include <cstdint>
#include <cstddef>
#include <functional>
#include <unordered_map>
#include <string>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <vector>
#include <arpa/inet.h>

class TunInterface;

// ─── IPv4 header parsing ──────────────────────────────────────────────────────
struct IPv4Header {
    uint8_t  ihl;         // header length in bytes
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;    // 6=TCP 17=UDP 1=ICMP
    uint16_t check;
    uint32_t saddr;       // host byte order
    uint32_t daddr;       // host byte order
};

inline bool parse_ipv4(const uint8_t* pkt, size_t len, IPv4Header& hdr) {
    if (len < 20) return false;
    if ((pkt[0] >> 4) != 4) return false;
    hdr.ihl      = (pkt[0] & 0x0F) * 4;
    hdr.tos      = pkt[1];
    hdr.tot_len  = (uint16_t(pkt[2]) << 8) | pkt[3];
    hdr.id       = (uint16_t(pkt[4]) << 8) | pkt[5];
    hdr.frag_off = (uint16_t(pkt[6]) << 8) | pkt[7];
    hdr.ttl      = pkt[8];
    hdr.protocol = pkt[9];
    hdr.check    = (uint16_t(pkt[10]) << 8) | pkt[11];
    hdr.saddr    = (uint32_t(pkt[12]) << 24) | (uint32_t(pkt[13]) << 16) |
                   (uint32_t(pkt[14]) << 8)  |  uint32_t(pkt[15]);
    hdr.daddr    = (uint32_t(pkt[16]) << 24) | (uint32_t(pkt[17]) << 16) |
                   (uint32_t(pkt[18]) << 8)  |  uint32_t(pkt[19]);
    return (size_t)hdr.tot_len <= len;
}

// ─── Routing ──────────────────────────────────────────────────────────────────
enum class RouteType { AEGS, BYPASS, BLOCK };

struct RouteEntry {
    uint32_t  network;   // host byte order
    uint32_t  netmask;   // host byte order
    RouteType type;
    int       metric;
    int       prefix_len;
};

using PacketSendFn = std::function<bool(const uint8_t* pkt, size_t len)>;

// ─── IpRouter ─────────────────────────────────────────────────────────────────
class IpRouter {
public:
    explicit IpRouter(TunInterface& tun, int mtu = 1400);
    ~IpRouter();

    // Register AEGS session sender (called for each outbound IP packet)
    void set_aegs_sender(PacketSendFn fn) { aegs_sender_ = std::move(fn); }

    // Add route via CIDR string e.g. "0.0.0.0/0", "10.0.0.0/8"
    bool add_route(const std::string& cidr, RouteType type, int metric = 100);

    // Start/stop TUN reader thread
    bool start();
    void stop();

    // Inject decrypted inbound packet from AEGS server into local TUN
    bool inject_packet(const uint8_t* pkt, size_t len);

    // Stats
    uint64_t packets_sent()     const { return pkts_sent_.load(std::memory_order_relaxed); }
    uint64_t packets_received() const { return pkts_recv_.load(std::memory_order_relaxed); }
    uint64_t packets_dropped()  const { return pkts_drop_.load(std::memory_order_relaxed); }
    uint64_t bytes_sent()       const { return bytes_sent_.load(std::memory_order_relaxed); }
    uint64_t bytes_recv()       const { return bytes_recv_.load(std::memory_order_relaxed); }

private:
    void      reader_loop();
    RouteType lookup_route(uint32_t dst_ip_host) const;

    TunInterface&            tun_;
    int                      mtu_;
    PacketSendFn             aegs_sender_;
    std::vector<RouteEntry>  routes_;
    mutable std::mutex       routes_mu_;

    std::atomic<bool>        running_{false};
    std::thread              reader_thread_;

    std::atomic<uint64_t>    pkts_sent_{0};
    std::atomic<uint64_t>    pkts_recv_{0};
    std::atomic<uint64_t>    pkts_drop_{0};
    std::atomic<uint64_t>    bytes_sent_{0};
    std::atomic<uint64_t>    bytes_recv_{0};
};

