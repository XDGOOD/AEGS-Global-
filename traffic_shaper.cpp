// ==============================================================================
// AEGS v4 "Pantheon" -- Traffic Shaper Implementation
// ==============================================================================
// thread_local mt19937 is seeded exactly once per OS thread on first call.
// Seeding uses std::random_device (syscall) for entropy; subsequent calls
// are pure PRNG with zero syscalls and zero heap allocations.
//
// semantic_pad() implements a bimodal distribution:
//   • Small payloads (≤200 B) → target ~256 B (QUIC ACK)
//   • Large payloads (>200 B) → target ~1350 B (full MTU QUIC frame)
//   • 5% chance of medium (512-768 B) to prevent fingerprinting the bimodal
// ==============================================================================

#include "traffic_shaper.h"

#include <algorithm>    // std::clamp (C++17), std::max
#include <chrono>
#include <cstring>      // std::memcpy
#include <limits>
#include <random>

// ---------------------------------------------------------------------------
// Thread-local PRNG state
// ---------------------------------------------------------------------------
namespace {

// Returns a reference to the per-thread Mersenne Twister.
// Initialised on first access per thread; never heap-allocated.
inline std::mt19937& thread_rng() noexcept {
    // Seed with random_device combined with high-res clock to ensure
    // uniqueness even if random_device is deterministic (e.g. some CI envs).
    thread_local std::mt19937 rng{
        []() -> uint32_t {
            std::random_device rd;
            uint32_t seed = rd();
            // Mix in thread-local timing to ensure distinct seeds per thread
            auto tp = std::chrono::high_resolution_clock::now()
                          .time_since_epoch()
                          .count();
            seed ^= static_cast<uint32_t>(tp & 0xFFFFFFFFu);
            seed ^= static_cast<uint32_t>(tp >> 32);
            return seed;
        }()
    };
    return rng;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
TrafficShaper::TrafficShaper(int jitter_ms, bool enabled) noexcept
    : enabled_(enabled),
      jitter_ms_(std::clamp(jitter_ms, 0, 1000)),
      jitter_us_max_(jitter_ms_ * 1000)
{}

// ---------------------------------------------------------------------------
// set_jitter_ms — update range at runtime
// ---------------------------------------------------------------------------
void TrafficShaper::set_jitter_ms(int ms) noexcept {
    jitter_ms_    = std::clamp(ms, 0, 1000);
    jitter_us_max_ = jitter_ms_ * 1000;
}

// ---------------------------------------------------------------------------
// next_delay_us — hot path, zero allocations
// ---------------------------------------------------------------------------
uint32_t TrafficShaper::next_delay_us() noexcept {
    if (!enabled_ || jitter_us_max_ == 0)
        return 0u;

    // Uniform distribution over [0, jitter_us_max_] inclusive.
    // std::uniform_int_distribution is a lightweight stack object.
    std::uniform_int_distribution<uint32_t> dist(
        0u, static_cast<uint32_t>(jitter_us_max_));
    return dist(thread_rng());
}

// ---------------------------------------------------------------------------
// semantic_pad — Bimodal Shaping for anti-ML DPI evasion
// ---------------------------------------------------------------------------
// Creates a packet-size distribution that looks like typical YouTube/QUIC:
//   • Cluster 1: ~256 bytes (ACKs, control, small queries)
//   • Cluster 2: ~1350 bytes (full MTU data frames)
//   • Occasional medium packets (5%) to add noise
//
// This defeats ML classifiers that rely on packet-size distributions to
// distinguish VPN traffic from legitimate QUIC/HTTP3 browsing.
// ---------------------------------------------------------------------------
size_t TrafficShaper::semantic_pad(size_t actual_payload_len) noexcept {
    if (!semantic_enabled_)
        return 0;

    auto& rng = thread_rng();

    // 5% chance: produce a "medium" packet (512-768 B) regardless of payload
    // This prevents the bimodal distribution from being a perfect fingerprint.
    std::uniform_int_distribution<int> pct_dist(0, 99);
    if (pct_dist(rng) < kMediumPct) {
        std::uniform_int_distribution<size_t> med_dist(kMediumLow, kMediumHigh);
        size_t target = med_dist(rng);
        size_t total_needed = kFrameHdr + actual_payload_len;
        if (total_needed >= target)
            return 0;
        return target - total_needed;
    }

    size_t total_with_hdr = kFrameHdr + actual_payload_len;

    if (actual_payload_len <= kSmallThresh) {
        // Small packet: target ~256 bytes (QUIC ACK profile)
        std::uniform_int_distribution<int> jitter(-kSmallJitter, kSmallJitter);
        int target = static_cast<int>(kSmallTarget) + jitter(rng);
        if (target < 0) target = 0;
        size_t t = static_cast<size_t>(target);
        if (total_with_hdr >= t)
            return 0;
        return t - total_with_hdr;
    } else {
        // Large packet: target ~1350 bytes (full MTU QUIC frame)
        if (total_with_hdr >= kLargeTarget) {
            // Already larger than target: minimal random padding
            std::uniform_int_distribution<size_t> small_pad(0, 32);
            return small_pad(rng);
        }
        std::uniform_int_distribution<int> jitter(-kLargeJitter, kLargeJitter);
        int target = static_cast<int>(kLargeTarget) + jitter(rng);
        if (target < 0) target = 0;
        size_t t = static_cast<size_t>(target);
        if (total_with_hdr >= t)
            return 0;
        return t - total_with_hdr;
    }
}

// ---------------------------------------------------------------------------
// fill_random_padding — Fast thread-local PRNG for internal AEAD padding
// ---------------------------------------------------------------------------
void TrafficShaper::fill_random_padding(uint8_t* dest, size_t len) noexcept {
    auto& rng = thread_rng();
    size_t i = 0;
    for (; i + 4 <= len; i += 4) {
        uint32_t val = rng();
        std::memcpy(dest + i, &val, 4);
    }
    if (i < len) {
        uint32_t val = rng();
        std::memcpy(dest + i, &val, len - i);
    }
}
