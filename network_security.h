#pragma once
// ==============================================================================
// AEGS v4 "Pantheon" -- Network Security & Reliability Suite
// - Component 1: KillSwitch (Hardware/Firewall-level Traffic Leak Prevention)
// - Component 2: DnsLeakProtector (Port 53 Lockdown & Resolver Shield)
// - Component 3: TransportFailureDetector (Loss monitoring for TCP fallback)
// - Component 4: AntiReplayFilter (RFC 6479 Multi-Word Sliding Window)
// ==============================================================================

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <array>
#include <cstddef>

class KillSwitch {
public:
    KillSwitch() noexcept;
    ~KillSwitch();

    KillSwitch(const KillSwitch&) = delete;
    KillSwitch& operator=(const KillSwitch&) = delete;

    // Activates firewall rules:
    // 1. Allow traffic to server_ip on [base_port .. base_port + port_count - 1]
    // 2. Allow all traffic on tun_iface (e.g. "aegs0")
    // 3. Allow loopback traffic ("lo" / 127.0.0.1)
    // 4. Allow DHCP client traffic (UDP 67/68) to preserve local leases
    // 5. DROP all other outbound traffic on physical interfaces
    bool enable(const std::string& server_ip,
                uint16_t           base_port,
                int                port_count  = 1,
                const std::string& tun_iface   = "aegs0") noexcept;

    // Reverts all firewall rules cleanly
    bool disable() noexcept;

    bool is_active() const noexcept { return active_; }

    // Generates the exact shell commands needed for audit/dry-run
    std::vector<std::string> generate_rules(const std::string& server_ip,
                                           uint16_t           base_port,
                                           int                port_count,
                                           const std::string& tun_iface) const;

    std::vector<std::string> generate_ipv6_rules() const;
    std::vector<std::string> generate_windows_rules(const std::string& server_ip,
                                                   uint16_t           base_port,
                                                   int                port_count) const;

private:
    bool active_;
    std::string server_ip_;
    uint16_t base_port_;
    int port_count_;
    std::string tun_iface_;
    std::vector<std::string> applied_cleanup_commands_;
    bool ipv6_blocked_;

    int execute_command(const std::string& cmd) const noexcept;
    bool is_ipv6_available() const noexcept;
};

class DnsLeakProtector {
public:
    DnsLeakProtector() noexcept;
    ~DnsLeakProtector();

    DnsLeakProtector(const DnsLeakProtector&) = delete;
    DnsLeakProtector& operator=(const DnsLeakProtector&) = delete;

    // Activates DNS leak shield:
    // 1. Blocks outbound UDP/TCP 53 on all non-TUN interfaces
    // 2. Overrides /etc/resolv.conf with secure nameserver (e.g. 10.8.0.1)
    // 3. Backs up previous resolv.conf for atomic restoration on exit
    // 4. Blocks outbound IPv6 UDP/TCP 53 to prevent IPv6 DNS leaks
    bool enable(const std::string& tun_iface   = "aegs0",
                const std::string& secure_dns  = "10.8.0.1") noexcept;

    bool disable() noexcept;

    bool is_active() const noexcept { return active_; }

    std::vector<std::string> generate_rules(const std::string& tun_iface) const;
    std::vector<std::string> generate_ipv6_rules() const;
    std::vector<std::string> generate_windows_rules(const std::string& secure_dns) const;

private:
    bool active_;
    std::string tun_iface_;
    std::string secure_dns_;
    std::string original_resolv_conf_;
    bool resolv_conf_backed_up_;
    bool is_symlink_;
    std::string symlink_target_;
    bool used_resolvectl_;
    bool ipv6_dns_blocked_;

    int execute_command(const std::string& cmd) const noexcept;
    bool is_ipv6_available() const noexcept;
};

class TransportFailureDetector {
public:
    explicit TransportFailureDetector(int max_consecutive_timeouts = 5,
                                      double max_blackout_sec = 15.0) noexcept;

    void record_success() noexcept;
    void record_timeout() noexcept;
    void record_packet_loss(size_t sent, size_t lost) noexcept;

    // Returns true if UDP is deemed completely blocked and fallback to TCP is required
    bool should_fallback_to_tcp() const noexcept;

    int consecutive_timeouts() const noexcept { return consecutive_timeouts_; }
    double loss_rate() const noexcept;

    void reset() noexcept;

private:
    int max_consecutive_timeouts_;
    double max_blackout_sec_;
    int consecutive_timeouts_;
    size_t total_sent_;
    size_t total_lost_;
    std::chrono::steady_clock::time_point last_success_time_;
};

// ==============================================================================
// Component 4: AntiReplayFilter (RFC 6479 Multi-Word Sliding Window)
// Default BITMAP_WORDS = 32 provides a 2048-packet window (256 bytes storage).
// BITMAP_WORDS = 16 provides a 1024-packet window (128 bytes storage).
// BITMAP_WORDS = 1 provides 64-packet window for backwards compatibility.
// Zero-allocation, thread-safe per-session instance, O(1) time complexity.
// ==============================================================================
template <size_t BITMAP_WORDS = 32>
class AntiReplayFilterT {
    static_assert(BITMAP_WORDS > 0 && (BITMAP_WORDS & (BITMAP_WORDS - 1)) == 0,
                  "BITMAP_WORDS must be a power of 2");
public:
    static constexpr size_t WORDS = BITMAP_WORDS;
    static constexpr size_t WINDOW_SIZE = BITMAP_WORDS * 64;

    AntiReplayFilterT() noexcept {
        reset();
    }

    void reset() noexcept {
        last_seq_ = 0;
        bitmap_.fill(0);
    }

    // Returns true if packet is replay or out of window (rejected).
    // Returns false if packet is valid and window is updated (accepted).
    bool check_and_update(uint64_t seq) noexcept {
        if (seq == 0) return true; // Sequence 0 is invalid/rejected

        if constexpr (BITMAP_WORDS == 1) {
            // 64-bit single-word sliding window (backwards-compatible)
            if (seq > last_seq_) {
                uint64_t diff = seq - last_seq_;
                if (diff < 64) {
                    bitmap_[0] = (bitmap_[0] << diff) | 1ULL;
                } else {
                    bitmap_[0] = 1ULL;
                }
                last_seq_ = seq;
                return false;
            }
            uint64_t diff = last_seq_ - seq;
            if (diff >= 64) return true;
            if (bitmap_[0] & (1ULL << diff)) return true;
            bitmap_[0] |= (1ULL << diff);
            return false;
        } else {
            // Multi-word RFC 6479 circular buffer sliding window
            if (seq > last_seq_) {
                uint64_t diff = seq - last_seq_;
                if (diff >= WINDOW_SIZE) {
                    bitmap_.fill(0);
                } else {
                    uint64_t last_word = last_seq_ >> 6;
                    uint64_t curr_word = seq >> 6;
                    for (uint64_t w = last_word + 1; w <= curr_word; ++w) {
                        bitmap_[w & (BITMAP_WORDS - 1)] = 0;
                    }
                }
                bitmap_[(seq >> 6) & (BITMAP_WORDS - 1)] |= (1ULL << (seq & 63));
                last_seq_ = seq;
                return false;
            }

            uint64_t diff = last_seq_ - seq;
            if (diff >= WINDOW_SIZE || ((last_seq_ >> 6) - (seq >> 6) >= BITMAP_WORDS)) {
                return true; // Out of sliding window (too old) -> reject
            }

            size_t word_idx = static_cast<size_t>((seq >> 6) & (BITMAP_WORDS - 1));
            uint64_t bit_mask = 1ULL << (seq & 63);

            if (bitmap_[word_idx] & bit_mask) {
                return true; // Already seen -> replay detected
            }

            bitmap_[word_idx] |= bit_mask;
            return false; // Valid out-of-order packet accepted
        }
    }

    uint64_t get_last_seq() const noexcept { return last_seq_; }
    uint64_t last_seq() const noexcept { return last_seq_; }
    constexpr size_t get_window_size() const noexcept { return WINDOW_SIZE; }
    constexpr size_t window_size() const noexcept { return WINDOW_SIZE; }

private:
    uint64_t last_seq_{0};
    std::array<uint64_t, BITMAP_WORDS> bitmap_{};
};

using AntiReplayFilter = AntiReplayFilterT<32>;
using AntiReplayFilter2048 = AntiReplayFilterT<32>;
using AntiReplayFilter1024 = AntiReplayFilterT<16>;
using AntiReplayFilter64 = AntiReplayFilterT<1>;

