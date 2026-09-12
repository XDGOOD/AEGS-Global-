// ==============================================================================
// AEGS v4 "Pantheon" -- Cryptographic Blackhole Responder Implementation
// ==============================================================================
// Each response strategy constructs a standards-compliant QUIC packet using
// entropy extracted from the probe itself (DCID, SCID bytes).  This makes
// every response look like a legitimate reply to the prober's "connection".
// ==============================================================================

#include "blackhole_responder.h"
#include <cstring>
#include <openssl/rand.h>

// ---------------------------------------------------------------------------
// Rate limiter (Token-bucket with packet & byte ceilings)
// ---------------------------------------------------------------------------
bool BlackholeResponder::should_respond(const std::string& ip, double now,
                                        double max_rate,
                                        size_t estimated_bytes) {
    if (max_rate <= 0.0) max_rate = kDefaultMaxRate;

    std::lock_guard<std::mutex> lock(mu_);
    auto it = rate_limits_.find(ip);
    if (it == rate_limits_.end()) {
        RateLimitEntry entry;
        entry.tokens = kBucketCapacity - 1.0; // Consume 1 token for this response
        entry.last_refill = now;
        entry.window_start = now;
        entry.total_packets = 1;
        entry.total_bytes = estimated_bytes;
        rate_limits_[ip] = entry;
        return true;
    }

    RateLimitEntry& entry = it->second;

    // Reset window if duration has elapsed
    if ((now - entry.window_start) >= kWindowDurationSec) {
        entry.window_start = now;
        entry.total_packets = 0;
        entry.total_bytes = 0;
    }

    // Enforce upper ceiling on total bytes/packets sent per IP (Audit issue 4.4)
    if (entry.total_packets >= kMaxPacketsPerIp || entry.total_bytes >= kMaxBytesPerIp) {
        return false;
    }

    // Refill tokens
    double dt = now - entry.last_refill;
    if (dt > 0.0) {
        double refill_rate = 1.0 / max_rate;
        entry.tokens += dt * refill_rate;
        if (entry.tokens > kBucketCapacity) {
            entry.tokens = kBucketCapacity;
        }
        entry.last_refill = now;
    }

    // Check if token bucket has at least 1 token
    if (entry.tokens < 1.0) {
        return false;
    }

    // Consume token and update packet & byte counters
    entry.tokens -= 1.0;
    entry.total_packets += 1;
    entry.total_bytes += estimated_bytes;

    // Periodic cleanup: drop entries older than 60 s to prevent unbounded growth
    if (rate_limits_.size() > 10000) {
        for (auto jt = rate_limits_.begin(); jt != rate_limits_.end(); ) {
            if (now - jt->second.last_refill > kWindowDurationSec)
                jt = rate_limits_.erase(jt);
            else
                ++jt;
        }
    }
    return true;
}

void BlackholeResponder::record_response(const std::string& ip, size_t bytes_sent) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = rate_limits_.find(ip);
    if (it != rate_limits_.end()) {
        if (bytes_sent > 80) {
            it->second.total_bytes += (bytes_sent - 80);
        }
    }
}

// ---------------------------------------------------------------------------
// Strategy selector
// ---------------------------------------------------------------------------
std::vector<uint8_t> BlackholeResponder::generate_response(
        const uint8_t* probe_data, size_t probe_len) {
    // Silently drop short probes to prevent UDP amplification attacks (Audit issue 4.4)
    if (!probe_data || probe_len < kMinProbeLen) return {};

    // Derive a pseudo-random selector from probe entropy (no CSPRNG call needed)
    uint8_t selector = 0;
    for (size_t i = 0; i < probe_len && i < 16; ++i)
        selector ^= probe_data[i];

    // 60% Version Negotiation, 20% Retry, 20% Connection Close
    uint8_t pct = selector % 100;
    if (pct < 60)
        return quic_version_negotiation(probe_data, probe_len);
    else if (pct < 80)
        return quic_retry(probe_data, probe_len);
    else
        return quic_connection_close(probe_data, probe_len);
}

// ---------------------------------------------------------------------------
// Strategy 1: QUIC Version Negotiation (RFC 9000 §17.2.1)
// ---------------------------------------------------------------------------
// Layout:
//   byte 0:        0x80 (Long Header, Version 0)
//   bytes 1-4:     0x00000000 (Version = 0 → Version Negotiation)
//   byte 5:        DCID Length (copied from probe's SCID, or 0)
//   bytes 6..6+D:  DCID (the prober's SCID echoed back)
//   next byte:     SCID Length (copied from probe's DCID len, or 0)
//   next S bytes:  SCID (the prober's DCID echoed back)
//   then:          Supported versions list (4 bytes each)
// ---------------------------------------------------------------------------
std::vector<uint8_t> BlackholeResponder::quic_version_negotiation(
        const uint8_t* probe_data, size_t probe_len) {
    // Extract DCID/SCID from probe if it looks like a QUIC long header
    uint8_t probe_dcid_len = 0;
    const uint8_t* probe_dcid = nullptr;
    uint8_t probe_scid_len = 0;
    const uint8_t* probe_scid = nullptr;

    if (probe_len >= 6 && (probe_data[0] & 0x80)) {
        // Long header format: byte5 = DCID len
        probe_dcid_len = probe_data[5];
        if (probe_dcid_len > 20) probe_dcid_len = 8;
        if (probe_len >= 6u + probe_dcid_len + 1u) {
            probe_dcid = probe_data + 6;
            probe_scid_len = probe_data[6 + probe_dcid_len];
            if (probe_scid_len > 20) probe_scid_len = 0;
            if (probe_len >= 7u + probe_dcid_len + probe_scid_len)
                probe_scid = probe_data + 7 + probe_dcid_len;
            else
                probe_scid_len = 0;
        }
    }
    // If not a QUIC header, use first few probe bytes as fake CIDs
    if (!probe_dcid && probe_len >= 8) {
        probe_dcid = probe_data;
        probe_dcid_len = 8;
    }

    // Build response: echo prober's SCID as our DCID, prober's DCID as our SCID
    // (as per RFC 9000 §17.2.1: DCID = source's SCID, SCID = source's DCID)
    size_t resp_len = 1 + 4 + 1 + probe_scid_len + 1 + probe_dcid_len + 8;
    std::vector<uint8_t> pkt(resp_len, 0);
    size_t off = 0;

    pkt[off++] = 0x80; // Long header flag
    // Version = 0 (triggers Version Negotiation per spec)
    pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x00;

    // DCID = prober's SCID
    pkt[off++] = probe_scid_len;
    if (probe_scid_len > 0 && probe_scid) {
        std::memcpy(&pkt[off], probe_scid, probe_scid_len);
        off += probe_scid_len;
    }

    // SCID = prober's DCID
    pkt[off++] = probe_dcid_len;
    if (probe_dcid_len > 0 && probe_dcid) {
        std::memcpy(&pkt[off], probe_dcid, probe_dcid_len);
        off += probe_dcid_len;
    }

    // Supported versions: QUIC v1 and draft-32
    pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x01;
    pkt[off++] = 0xff; pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x20;

    pkt.resize(off);
    return pkt;
}

// ---------------------------------------------------------------------------
// Strategy 2: QUIC Retry (RFC 9000 §17.2.5)
// ---------------------------------------------------------------------------
std::vector<uint8_t> BlackholeResponder::quic_retry(
        const uint8_t* probe_data, size_t probe_len) {
    // Retry packet: Long Header with type = Retry (0xF0 | random low nibble)
    // Layout:
    //   0:    0xF0 | (random & 0x0F)   -- Retry type
    //   1-4:  QUIC version 1
    //   5:    DCID len
    //   6+D:  DCID (prober's SCID echoed)
    //   next: SCID len
    //   next: SCID (server-generated, 8 bytes random)
    //   next: Retry Token (16 bytes, derived from probe entropy)
    //   last 16 bytes: Retry Integrity Tag (random, since prober can't verify)

    uint8_t probe_dcid_len = 0;
    const uint8_t* probe_dcid = nullptr;

    if (probe_len >= 6 && (probe_data[0] & 0x80)) {
        probe_dcid_len = probe_data[5];
        if (probe_dcid_len > 20) probe_dcid_len = 8;
        if (probe_len >= 6u + probe_dcid_len)
            probe_dcid = probe_data + 6;
    }
    if (!probe_dcid && probe_len >= 8) {
        probe_dcid = probe_data;
        probe_dcid_len = 8;
    }

    uint8_t server_scid[8];
    RAND_bytes(server_scid, 8);

    uint8_t retry_token[16];
    // Derive token from probe entropy for deterministic-looking behavior
    for (int i = 0; i < 16; ++i)
        retry_token[i] = (i < (int)probe_len) ? (probe_data[i] ^ 0xA5) : 0x42;

    uint8_t integrity_tag[16];
    RAND_bytes(integrity_tag, 16);

    uint8_t type_byte = 0xF0;
    if (probe_len > 0)
        type_byte |= (probe_data[0] & 0x0F);

    size_t pkt_len = 1 + 4 + 1 + probe_dcid_len + 1 + 8 + 16 + 16;
    std::vector<uint8_t> pkt(pkt_len, 0);
    size_t off = 0;

    pkt[off++] = type_byte;
    // QUIC version 1
    pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x01;

    // DCID = prober's DCID echoed
    pkt[off++] = probe_dcid_len;
    if (probe_dcid_len > 0 && probe_dcid) {
        std::memcpy(&pkt[off], probe_dcid, probe_dcid_len);
        off += probe_dcid_len;
    }

    // SCID = server-generated
    pkt[off++] = 8;
    std::memcpy(&pkt[off], server_scid, 8);
    off += 8;

    // Retry Token
    std::memcpy(&pkt[off], retry_token, 16);
    off += 16;

    // Retry Integrity Tag (last 16 bytes)
    std::memcpy(&pkt[off], integrity_tag, 16);
    off += 16;

    pkt.resize(off);
    return pkt;
}

// ---------------------------------------------------------------------------
// Strategy 3: QUIC Connection Close (RFC 9000 §19.19)
// ---------------------------------------------------------------------------
std::vector<uint8_t> BlackholeResponder::quic_connection_close(
        const uint8_t* probe_data, size_t probe_len) {
    // In real QUIC, 1-RTT short header packets are ALWAYS fully encrypted with AEAD.
    // There is NEVER plaintext ASCII (such as "unsupported version") on the wire.
    // To an external observer or DPI, all bytes after DCID must look like high-entropy
    // ciphertext + Poly1305/GCM authentication tag (Shannon entropy > 7.5).
    uint8_t dcid[8] = {0};
    size_t copy_len = (probe_len < 8) ? probe_len : 8;
    if (probe_len > 0) std::memcpy(dcid, probe_data, copy_len);

    // Realistic 1-RTT packet length: header(1) + dcid(8) + encrypted payload + tag (41B) = 50B
    size_t pkt_len = 1 + 8 + 41;
    std::vector<uint8_t> pkt(pkt_len, 0);
    size_t off = 0;

    // Short header with random low bits (Fixed bit 0x40 set)
    uint8_t hdr_byte = 0x40;
    if (probe_len > 1) hdr_byte |= (probe_data[1] & 0x3F);
    pkt[off++] = hdr_byte;

    // DCID
    std::memcpy(&pkt[off], dcid, 8);
    off += 8;

    // Remainder of packet is AEAD ciphertext simulation: 100% cryptographic entropy,
    // zero identifiable plain strings.
    RAND_bytes(&pkt[off], pkt_len - off);

    return pkt;
}
