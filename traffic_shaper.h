#pragma once
// ==============================================================================
// AEGS v4 "Pantheon" -- Traffic Shaping / Jitter (Component 3: DPI bypass)
// ==============================================================================
// Adds a uniform random delay [0, jitter_ms * 1000] microseconds before each
// outbound packet to break packet-timing fingerprints used by advanced DPI.
//
// Design:
//   • thread_local std::mt19937 — PRNG seeded once per thread, zero heap alloc
//     in the hot path.
//   • next_delay_us() returns immediately (no actual sleeping) so the caller
//     decides how to apply the delay (e.g. usleep / io_uring timer).
//   • When disabled, next_delay_us() returns 0 with no PRNG call.
//
// AEGS v4 Extension — Semantic Padding ("Bimodal Shaping"):
//   • semantic_pad(payload_len) computes padding to create a bimodal packet-
//     size distribution that mimics YouTube / QUIC traffic patterns.
//   • Small packets (≤200 B) are padded to ~256 B (QUIC ACK profile).
//   • Large packets (>200 B) are padded to ~1350 B (full MTU QUIC frames).
//   • 5% probability of a "medium" packet (512-768 B) prevents the bimodal
//     distribution from becoming a fingerprint itself.
// ==============================================================================

#include <cstdint>
#include <cstddef>

class TrafficShaper {
public:
    // jitter_ms:  maximum jitter in milliseconds (clamped to [0, 1000])
    // enabled:    if false, next_delay_us() always returns 0
    explicit TrafficShaper(int jitter_ms = 5, bool enabled = false) noexcept;

    // Returns microseconds to sleep before sending the next packet.
    // Range: [0, jitter_ms_ * 1000] inclusive.
    // Thread-safe: uses thread_local PRNG (no shared state, no locks).
    uint32_t next_delay_us() noexcept;

    // --- Semantic Padding (Bimodal Shaping) ---
    // Compute the number of padding bytes to add for a bimodal distribution.
    // actual_payload_len: real IP packet size being encapsulated.
    // Returns: padding byte count (0 if semantic padding is disabled).
    // Thread-safe: uses thread_local PRNG.
    size_t semantic_pad(size_t actual_payload_len) noexcept;

    // Fast fill padding bytes inside AEAD using thread_local PRNG (zero syscalls)
    static void fill_random_padding(uint8_t* dest, size_t len) noexcept;

    // --- Accessors ---
    bool enabled()              const noexcept { return enabled_; }
    void set_enabled(bool e)          noexcept { enabled_ = e; }
    int  jitter_ms()            const noexcept { return jitter_ms_; }
    void set_jitter_ms(int ms)        noexcept;

    bool semantic_enabled()           const noexcept { return semantic_enabled_; }
    void set_semantic_enabled(bool e)       noexcept { semantic_enabled_ = e; }

private:
    bool enabled_;
    int  jitter_ms_;     // max jitter [ms], clamped to [0, 1000]
    int  jitter_us_max_; // precomputed: jitter_ms_ * 1000 (microseconds)
    bool semantic_enabled_ = false;

    // Internal constants for bimodal targets
    static constexpr size_t kFrameHdr     = 2;
    static constexpr size_t kSmallThresh  = 200;   // bytes
    static constexpr size_t kSmallTarget  = 256;   // QUIC ACK profile
    static constexpr size_t kLargeTarget  = 1350;  // Full MTU QUIC frame
    static constexpr int    kSmallJitter  = 16;    // ±16 bytes jitter
    static constexpr int    kLargeJitter  = 32;    // ±32 bytes jitter
    static constexpr size_t kMediumLow    = 512;
    static constexpr size_t kMediumHigh   = 768;
    static constexpr int    kMediumPct    = 5;     // 5% medium packet chance
};
