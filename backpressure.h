#pragma once
// ==============================================================================
// AEGS v4 "Pantheon" -- Backpressure & Congestion Guard
// ==============================================================================
// Prevents memory exhaustion (OOM) and Bufferbloat during traffic bursts,
// packet drops, and transport congestion.
//
// In an L3 VPN tunnel, reading indefinitely from a TUN interface while the
// outbound UDP socket buffer is congested causes severe bufferbloat, memory
// exhaustion, and socket drops.
//
// BackpressureController enforces:
//   1. Bounded Batching: Limits TUN read bursts to kMaxTunBatch packets per tick.
//   2. Socket Egress Monitoring: Detects EAGAIN, ENOBUFS, EWOULDBLOCK on sendto().
//   3. TCP Upstream Flow Control: Pausing TUN reads when UDP is congested fills
//      the kernel TUN queue, naturally signaling the OS TCP stack to shrink
//      its TCP Congestion Window (TCP flow control / zero-window) without OOM.
//   4. Zero Heap Allocations: Completely lock-free / low-overhead primitives.
// ==============================================================================

#include <cstdint>
#include <cstddef>
#include <chrono>
#include <cerrno>
#include <algorithm>

class BackpressureController {
public:
    static constexpr size_t kDefaultMaxTunBatch = 64;
    static constexpr int kMaxConsecutiveFailures = 3;
    static constexpr int64_t kCooldownMs = 15; // 15ms backoff after congestion

    explicit BackpressureController(size_t max_tun_batch = kDefaultMaxTunBatch) noexcept
        : max_tun_batch_(max_tun_batch),
          consecutive_failures_(0),
          is_congested_(false),
          last_failure_time_(std::chrono::steady_clock::time_point::min()) {}

    // Maximum packets to drain from TUN in a single epoll iteration
    size_t max_tun_batch() const noexcept {
        if (is_congested()) {
            return std::max<size_t>(1, max_tun_batch_ / 8); // Throttle drain when congested
        }
        return max_tun_batch_;
    }

    // Call after successful sendto()
    void record_egress_success() noexcept {
        consecutive_failures_ = 0;
        is_congested_ = false;
    }

    // Call when sendto() fails with EAGAIN / ENOBUFS / EWOULDBLOCK
    void record_egress_failure(int err) noexcept {
        if (err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS) {
            consecutive_failures_++;
            last_failure_time_ = std::chrono::steady_clock::now();
            if (consecutive_failures_ >= kMaxConsecutiveFailures) {
                is_congested_ = true;
            }
        }
    }

    // Checks whether the egress path is currently congested
    bool is_congested() const noexcept {
        if (!is_congested_) return false;
        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_failure_time_).count();
        if (elapsed_ms >= kCooldownMs) {
            // Cooldown period elapsed: probe recovery
            is_congested_ = false;
            consecutive_failures_ = 0;
            return false;
        }
        return true;
    }

    // Returns true if TUN reading should be paused this tick to apply backpressure
    bool should_pause_tun() const noexcept {
        return is_congested();
    }

private:
    size_t max_tun_batch_;
    mutable int consecutive_failures_;
    mutable bool is_congested_;
    mutable std::chrono::steady_clock::time_point last_failure_time_;
};
