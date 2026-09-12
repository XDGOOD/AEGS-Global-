#pragma once
// ==============================================================================
// AEGS v5 "Pantheon" -- AIMD Adaptive Backpressure & Congestion Controller
// (Stage 12 & 13 of Target Roadmap)
// ==============================================================================
// Features:
// 1. AIMD Dynamic Batch Sizing:
//    - Multiplicative Decrease: Halves batch size on EAGAIN/ENOBUFS (64 -> 32 -> 16 -> 8 -> 4)
//    - Additive Increase: Gradually scales back up to 64 upon sustained success
// 2. Adaptive Egress Pacing:
//    - Introduces microsecond-level pacing delay to smoothly drain kernel UDP buffers
// 3. Fail-Safe TCP Flow Control:
//    - Pauses TUN reads during congestion to signal the upstream TCP stack
// 4. Zero Allocations, Low Overhead:
//    - Pure atomic/integer state arithmetic with 0 heap allocations
// ==============================================================================

#include <cstdint>
#include <cstddef>
#include <chrono>
#include <cerrno>
#include <algorithm>
#include <atomic>

class BackpressureController {
public:
    static constexpr size_t kDefaultMaxBatch = 64;
    static constexpr size_t kDefaultMinBatch = 4;
    static constexpr int kMaxConsecutiveFailures = 2;
    static constexpr int64_t kBaseCooldownMs = 10;
    static constexpr size_t kAdditiveIncreaseInterval = 64; // Scale up every 64 successful packets

    explicit BackpressureController(size_t max_tun_batch = kDefaultMaxBatch,
                                   size_t min_tun_batch = kDefaultMinBatch) noexcept
        : max_batch_(max_tun_batch),
          min_batch_(min_tun_batch),
          current_batch_(max_tun_batch),
          consecutive_failures_(0),
          consecutive_successes_(0),
          congestion_events_(0),
          pacing_delay_us_(0),
          is_congested_(false),
          last_failure_time_(std::chrono::steady_clock::time_point::min()) {}

    // AIMD Dynamic Batch: returns current adaptive batch ceiling
    size_t max_tun_batch() const noexcept {
        if (is_congested()) {
            return std::max<size_t>(min_batch_, current_batch_);
        }
        return current_batch_;
    }

    // Call after successful UDP sendto() / sendmmsg()
    void record_egress_success() noexcept {
        consecutive_failures_ = 0;
        consecutive_successes_++;

        if (is_congested_) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_failure_time_).count();
            if (elapsed_ms >= dynamic_cooldown_ms()) {
                is_congested_ = false;
            }
        }

        // Additive Increase: gradually step up batch size
        if (consecutive_successes_ >= kAdditiveIncreaseInterval) {
            consecutive_successes_ = 0;
            if (current_batch_ < max_batch_) {
                current_batch_ = std::min<size_t>(max_batch_, current_batch_ + 2);
            }
            if (pacing_delay_us_ > 0) {
                pacing_delay_us_ = (pacing_delay_us_ > 50) ? (pacing_delay_us_ - 50) : 0;
            }
        }
    }

    // Call when sendto() / sendmmsg() fails with EAGAIN / ENOBUFS / EWOULDBLOCK
    void record_egress_failure(int err) noexcept {
        if (err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS) {
            consecutive_failures_++;
            consecutive_successes_ = 0;
            last_failure_time_ = std::chrono::steady_clock::now();

            if (consecutive_failures_ >= kMaxConsecutiveFailures) {
                is_congested_ = true;
                congestion_events_++;

                // Multiplicative Decrease: halve batch size down to min_batch
                current_batch_ = std::max<size_t>(min_batch_, current_batch_ / 2);

                // Add pacing delay to allow kernel socket buffer to drain
                pacing_delay_us_ = std::min<uint32_t>(2000, pacing_delay_us_ + 200);
            }
        }
    }

    // Checks whether egress path is currently congested
    bool is_congested() const noexcept {
        if (!is_congested_) return false;
        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_failure_time_).count();
        if (elapsed_ms >= dynamic_cooldown_ms()) {
            is_congested_ = false;
            consecutive_failures_ = 0;
            return false;
        }
        return true;
    }

    // Flow control: pause TUN read during acute congestion
    bool should_pause_tun() const noexcept {
        return is_congested();
    }

    // Adaptive microsecond pacing delay
    uint32_t pacing_delay_us() const noexcept {
        return is_congested() ? pacing_delay_us_ : 0;
    }

    size_t current_batch() const noexcept { return current_batch_; }
    uint64_t congestion_events() const noexcept { return congestion_events_; }

private:
    int64_t dynamic_cooldown_ms() const noexcept {
        // Backoff cooldown slightly increases with repeat congestion events (up to 50ms)
        return std::min<int64_t>(50, kBaseCooldownMs + static_cast<int64_t>(consecutive_failures_ * 5));
    }

    size_t   max_batch_;
    size_t   min_batch_;
    size_t   current_batch_;
    int      consecutive_failures_;
    size_t   consecutive_successes_;
    uint64_t congestion_events_;
    uint32_t pacing_delay_us_;
    mutable bool is_congested_;
    mutable std::chrono::steady_clock::time_point last_failure_time_;
};
