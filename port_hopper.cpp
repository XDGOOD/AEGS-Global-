// ==============================================================================
// AEGS v4 "Pantheon" -- Port Hopping Implementation
// ==============================================================================
// HMAC-SHA256 is computed with stack-only buffers; no heap alloc in hot path.
// OpenSSL HMAC_CTX is stack-allocated via HMAC() one-shot API to avoid
// EVP_MD_CTX heap allocation in the data path.
// ==============================================================================

#include "port_hopper.h"

#include <cstring>
#include <ctime>

#include <openssl/hmac.h>
#include <openssl/sha.h>

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
PortHopper::PortHopper(uint16_t base_port,
                       int      count,
                       uint32_t hop_interval_sec) noexcept
    : base_port_(base_port),
      count_(count < 1 ? 1 : (count > 64 ? 64 : count)),
      hop_interval_sec_(hop_interval_sec < 1 ? 1 : hop_interval_sec)
{}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------
std::vector<uint16_t> PortHopper::server_ports() const {
    std::vector<uint16_t> ports;
    ports.reserve(static_cast<size_t>(count_));
    for (int i = 0; i < count_; ++i)
        ports.push_back(static_cast<uint16_t>(base_port_ + i));
    return ports;
}

// ---------------------------------------------------------------------------
// Internal: HMAC-SHA256(session_key, epoch_be64) → hmac_out[32]
// Uses OpenSSL one-shot HMAC() which does NOT allocate on the heap.
// Returns false only if OpenSSL internal error (should never happen in prod).
// ---------------------------------------------------------------------------
bool PortHopper::compute_hmac(const uint8_t session_key[32],
                              uint64_t      epoch_be,
                              uint8_t       hmac_out[32]) const noexcept {
    // Encode epoch as big-endian 8 bytes (consistent across platforms)
    uint8_t epoch_buf[8];
    epoch_buf[0] = static_cast<uint8_t>(epoch_be >> 56);
    epoch_buf[1] = static_cast<uint8_t>(epoch_be >> 48);
    epoch_buf[2] = static_cast<uint8_t>(epoch_be >> 40);
    epoch_buf[3] = static_cast<uint8_t>(epoch_be >> 32);
    epoch_buf[4] = static_cast<uint8_t>(epoch_be >> 24);
    epoch_buf[5] = static_cast<uint8_t>(epoch_be >> 16);
    epoch_buf[6] = static_cast<uint8_t>(epoch_be >>  8);
    epoch_buf[7] = static_cast<uint8_t>(epoch_be);

    unsigned int out_len = SHA256_DIGEST_LENGTH;
    const uint8_t* result = HMAC(EVP_sha256(),
                                 session_key, 32,
                                 epoch_buf,   sizeof(epoch_buf),
                                 hmac_out,    &out_len);
    return (result != nullptr) && (out_len == SHA256_DIGEST_LENGTH);
}

// ---------------------------------------------------------------------------
// Internal: epoch → port
// ---------------------------------------------------------------------------
uint16_t PortHopper::epoch_to_port(const uint8_t session_key[32],
                                   uint64_t      epoch) const noexcept {
    uint8_t hmac_out[SHA256_DIGEST_LENGTH];
    if (!compute_hmac(session_key, epoch, hmac_out)) {
        // Fallback to base port on OpenSSL error (should never occur)
        return base_port_;
    }
    // Use first 4 bytes as little-endian uint32 to determine index
    uint32_t val = (static_cast<uint32_t>(hmac_out[0])      )
                 | (static_cast<uint32_t>(hmac_out[1]) <<  8)
                 | (static_cast<uint32_t>(hmac_out[2]) << 16)
                 | (static_cast<uint32_t>(hmac_out[3]) << 24);
    int index = static_cast<int>(val % static_cast<uint32_t>(count_));
    return static_cast<uint16_t>(base_port_ + index);
}

// ---------------------------------------------------------------------------
// Client side: current active port
// ---------------------------------------------------------------------------
uint16_t PortHopper::current_port(const uint8_t session_key[32]) const noexcept {
    uint64_t epoch = static_cast<uint64_t>(
        static_cast<uint64_t>(std::time(nullptr)) / hop_interval_sec_);
    return epoch_to_port(session_key, epoch);
}

// ---------------------------------------------------------------------------
// Client side: {current, next} port window
// ---------------------------------------------------------------------------
std::pair<uint16_t, uint16_t>
PortHopper::port_window(const uint8_t session_key[32]) const noexcept {
    uint64_t epoch = static_cast<uint64_t>(
        static_cast<uint64_t>(std::time(nullptr)) / hop_interval_sec_);
    return {epoch_to_port(session_key, epoch),
            epoch_to_port(session_key, epoch + 1)};
}

// ---------------------------------------------------------------------------
// Server side: validate incoming packet port against hopping window
// ---------------------------------------------------------------------------
bool PortHopper::is_valid_port(const uint8_t session_key[32], uint16_t received_port) const noexcept {
    if (count_ <= 1) return received_port == base_port_;
    uint64_t epoch = static_cast<uint64_t>(
        static_cast<uint64_t>(std::time(nullptr)) / hop_interval_sec_);
    if (epoch_to_port(session_key, epoch) == received_port) return true;
    if (epoch > 0 && epoch_to_port(session_key, epoch - 1) == received_port) return true;
    if (epoch_to_port(session_key, epoch + 1) == received_port) return true;
    return false;
}

