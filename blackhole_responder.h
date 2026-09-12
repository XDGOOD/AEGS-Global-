#pragma once
// ==============================================================================
// AEGS v4 "Pantheon" -- Cryptographic Blackhole Responder (Anti Active Probing)
// ==============================================================================
// When the server receives an invalid/probe packet that fails authentication,
// instead of silently dropping or sending a generic error, it responds with
// a realistic QUIC-looking packet derived from the probe's own entropy.
//
// Effect: Active scanners (censorship probers) conclude this is an ordinary
// QUIC server that doesn't support their requested version, and mark the IP
// as benign.  Three response strategies are rotated pseudo-randomly:
//
//   1. QUIC Version Negotiation  (60%)  -- "I only support version X"
//   2. QUIC Retry                (20%)  -- "Please retry with this token"
//   3. QUIC Connection Close     (20%)  -- "Protocol violation, go away"
//
// All responses are rate-limited per source IP using a token-bucket rate
// limiter with packet and byte ceilings to prevent UDP amplification attacks.
// ==============================================================================

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

class BlackholeResponder {
public:
    BlackholeResponder() = default;

    // Minimum incoming probe size check (Audit issue 4.4):
    // Probes shorter than kMinProbeLen (20 bytes) are silently dropped to prevent
    // active probers from using the server as a UDP amplification reflector.
    static constexpr size_t kMinProbeLen = 20;

    // Token-bucket rate limiter parameters & upper ceilings per IP
    static constexpr double kDefaultMaxRate    = 0.20;    // Minimum seconds between responses (5 pkts/sec)
    static constexpr double kBucketCapacity    = 1.0;     // Burst ceiling in tokens
    static constexpr double kWindowDurationSec = 60.0;    // Rate limiting & ceiling window (60s)
    static constexpr size_t kMaxPacketsPerIp   = 50;      // Upper ceiling on total packets sent per IP per window
    static constexpr size_t kMaxBytesPerIp     = 8192;    // Upper ceiling on total bytes sent per IP per window (8 KB)

    // Generate a QUIC-looking response derived from probe entropy.
    // probe_data / probe_len: the raw invalid packet received.
    // Returns empty vector if packet is too short (< kMinProbeLen) to prevent amplification.
    std::vector<uint8_t> generate_response(const uint8_t* probe_data,
                                           size_t         probe_len);

    // Per-IP token-bucket rate limiter: returns true if we should respond.
    // max_rate: minimum seconds between responses to the same IP.
    // estimated_bytes: estimated response size for byte budget accounting.
    bool should_respond(const std::string& ip, double now,
                        double max_rate = kDefaultMaxRate,
                        size_t estimated_bytes = 80);

    // Record actual response bytes sent to update the byte budget accounting.
    void record_response(const std::string& ip, size_t bytes_sent);

private:
    // --- Response generators ---
    std::vector<uint8_t> quic_version_negotiation(const uint8_t* probe_data,
                                                   size_t         probe_len);
    std::vector<uint8_t> quic_retry(const uint8_t* probe_data,
                                    size_t         probe_len);
    std::vector<uint8_t> quic_connection_close(const uint8_t* probe_data,
                                               size_t         probe_len);

    // Per-IP token bucket & window rate limiter entry
    struct RateLimitEntry {
        double tokens        = 1.0;  // Available packet tokens
        double last_refill   = 0.0;  // Timestamp of last token bucket refill
        size_t total_packets = 0;    // Total packets sent in current window
        size_t total_bytes   = 0;    // Total bytes sent in current window
        double window_start  = 0.0;  // Start timestamp of current window
    };

    mutable std::mutex mu_;
    std::unordered_map<std::string, RateLimitEntry> rate_limits_;
};
