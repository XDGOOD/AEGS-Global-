// ==============================================================================
// AEGS v4 "Pantheon" -- Protocol Mimicry Implementation
// ==============================================================================
// wrap_quic_initial() performs a single memmove to make room for the 24-byte
// RFC 9000 header — no heap allocation occurs.
// Randomized CIDs (DCID & SCID) and dynamic version negotiation eliminate
// static signatures on the wire (fixing Audit issue 4.3).
// ==============================================================================

#include "protocol_mimicry.h"
#include <cstring>
#include <openssl/rand.h>

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
ProtocolMimicry::ProtocolMimicry(Mode mode, uint32_t quic_version) noexcept
    : mode_(mode),
      header_size_(mode == Mode::NONE ? 0 : kQuicHeaderSize),
      quic_version_(quic_version)
{}

void ProtocolMimicry::set_mode(Mode mode) noexcept {
    mode_ = mode;
    header_size_ = (mode == Mode::NONE ? 0 : kQuicHeaderSize);
}

// ---------------------------------------------------------------------------
// wrap_quic_initial()
// ---------------------------------------------------------------------------
size_t ProtocolMimicry::wrap_quic_initial(uint8_t*       buf,
                                          size_t         data_len,
                                          size_t         buf_capacity,
                                          const uint8_t  session_seed[2],
                                          uint32_t       quic_version) noexcept {
    // Ensure there is room for the header
    if (data_len + kQuicHeaderSize > buf_capacity)
        return data_len; // Cannot prepend — return unchanged length as a safe fallback

    // Shift payload right to make room (overlapping move, so memmove)
    std::memmove(buf + kQuicHeaderSize, buf, data_len);

    uint8_t rand_bytes[18];
    RAND_bytes(rand_bytes, sizeof(rand_bytes));

    // Dynamic Version Selection per RFC 9000 / RFC 9369
    uint32_t version = quic_version;
    if (version == 0) {
        // Pseudo-random selection among supported versions and dynamic version negotiation
        static const uint32_t kVersions[] = {
            kQuicVersion1,
            kQuicVersion2,
            kQuicDraft29,
            kQuicDraft32,
            kQuicVerNeg
        };
        uint8_t v_idx = rand_bytes[0] % 5;
        version = kVersions[v_idx];
    }

    // Byte 0: Header Form & Type Bits
    // In RFC 9000 §17.2, Initial header has bits 0xC0 with lowest 4 bits protected/randomized (0xC0..0xCF).
    // If version is 0 (Version Negotiation, RFC 9000 §17.2.1), bit 7=1, bits 0-6 are random.
    if (version == kQuicVerNeg) {
        buf[0] = static_cast<uint8_t>(0x80 | (rand_bytes[1] & 0x7F));
    } else {
        buf[0] = static_cast<uint8_t>(0xC0 | (rand_bytes[1] & 0x0F));
    }

    // Bytes 1-4: Version (Big Endian)
    buf[1] = static_cast<uint8_t>((version >> 24) & 0xFF);
    buf[2] = static_cast<uint8_t>((version >> 16) & 0xFF);
    buf[3] = static_cast<uint8_t>((version >> 8) & 0xFF);
    buf[4] = static_cast<uint8_t>(version & 0xFF);

    // Byte 5: DCID Length = 8
    buf[5] = 0x08;

    // Bytes 6-13: Destination Connection ID (DCID, 8 bytes randomized)
    // If session_seed is provided, incorporate it into DCID prefix, with rest randomized
    if (session_seed != nullptr) {
        buf[6] = session_seed[0];
        buf[7] = session_seed[1];
        std::memcpy(&buf[8], &rand_bytes[2], 6);
    } else {
        std::memcpy(&buf[6], &rand_bytes[2], 8);
    }

    // Byte 14: SCID Length = 8
    buf[14] = 0x08;

    // Bytes 15-22: Source Connection ID (SCID, 8 bytes randomized)
    std::memcpy(&buf[15], &rand_bytes[10], 8);

    // Byte 23: Token Length = 0x00
    buf[23] = 0x00;

    return data_len + kQuicHeaderSize;
}

// ---------------------------------------------------------------------------
// wrap()
// ---------------------------------------------------------------------------
size_t ProtocolMimicry::wrap(uint8_t*       buf,
                             size_t         data_len,
                             size_t         buf_capacity,
                             const uint8_t  session_seed[2]) noexcept {
    if (mode_ == Mode::NONE)
        return data_len;

    uint32_t v = quic_version_;
    if (mode_ == Mode::VERSION_NEGOTIATION) {
        v = kQuicVerNeg;
    }

    return wrap_quic_initial(buf, data_len, buf_capacity, session_seed, v);
}
