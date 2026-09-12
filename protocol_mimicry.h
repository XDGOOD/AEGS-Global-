#pragma once
// ==============================================================================
// AEGS v4 "Pantheon" -- Protocol Mimicry (Component 3: DPI bypass)
// ==============================================================================
// Wraps outbound UDP packets with a dynamic QUIC Initial or Version Negotiation
// header so that stateless DPI engines classify the flow as benign QUIC traffic.
//
// Complies with RFC 9000 & RFC 9369:
// - Eliminates static 6-byte signature (0xC0 0x00 0x00 0x00 0x01 0x08).
// - Randomizes Connection IDs (DCID: 8 bytes, SCID: 8 bytes).
// - Masks low 4 bits of the header byte (simulating wire header protection).
// - Supports dynamic version negotiation and dynamic QUIC versions (v1, v2, draft-29, draft-32).
//
// RFC 9000 Long Header layout (24 bytes):
//   byte 0:       0xC0 | (random & 0x0F)   — Long Header, Initial type, protected low bits
//                 (or 0x80 | (random & 0x7F) for Version Negotiation)
//   bytes 1-4:    Dynamic QUIC version (v1, v2, drafts, or 0x00000000 for version neg)
//   byte 5:       0x08                     — DCID Length = 8
//   bytes 6-13:   8 bytes DCID             — Randomized / session-derived Connection ID
//   byte 14:      0x08                     — SCID Length = 8
//   bytes 15-22:  8 bytes SCID             — Randomized Connection ID
//   byte 23:      0x00                     — Token Length = 0
//
// The real AEGS payload follows immediately after the mimicry header.
// On the receive side call unwrap_offset() to skip the header.
// ==============================================================================

#include <cstddef>
#include <cstdint>

class ProtocolMimicry {
public:
    enum class Mode {
        NONE,                // No mimicry — pass through unchanged
        QUIC_INITIAL,        // Prepend RFC 9000 QUIC Initial header with randomized CIDs/version
        HTTP3,               // Prepend RFC 9000 QUIC/HTTP3 header
        VERSION_NEGOTIATION  // Prepend RFC 9000 QUIC Version Negotiation header
    };

    // Supported QUIC versions per RFC 9000 / RFC 9369
    static constexpr uint32_t kQuicVersion1 = 0x00000001; // RFC 9000 QUIC v1
    static constexpr uint32_t kQuicVersion2 = 0x6B3343CF; // RFC 9369 QUIC v2
    static constexpr uint32_t kQuicDraft29  = 0xFF00001D; // draft-29
    static constexpr uint32_t kQuicDraft32  = 0xFF000020; // draft-32
    static constexpr uint32_t kQuicVerNeg   = 0x00000000; // RFC 9000 Version Negotiation

    static constexpr size_t kQuicHeaderSize = 24;

    explicit ProtocolMimicry(Mode mode = Mode::NONE, uint32_t quic_version = 0) noexcept;

    // Direct helper to wrap a buffer with an RFC 9000 QUIC Initial header with randomized
    // Connection IDs (DCID, SCID) and dynamic version selection.
    // session_seed: optional 2-byte seed to mix into DCID; if nullptr, fully randomized.
    // quic_version: target version, or 0 for dynamic version selection.
    static size_t wrap_quic_initial(uint8_t*       buf,
                                    size_t         data_len,
                                    size_t         buf_capacity,
                                    const uint8_t  session_seed[2] = nullptr,
                                    uint32_t       quic_version = 0) noexcept;

    // Member function alias matching wrap_quic_initial naming from audit
    size_t wrap_quic_initial(uint8_t*       buf,
                             size_t         data_len,
                             size_t         buf_capacity,
                             const uint8_t  session_seed[2] = nullptr) noexcept {
        return wrap(buf, data_len, buf_capacity, session_seed);
    }

    // Prepend the mimicry header in-place.
    // The caller MUST ensure buf_capacity >= data_len + header_size_.
    // Data bytes [0..data_len) are shifted right by header_size_ bytes.
    // Returns new total packet length, or data_len if Mode::NONE.
    size_t wrap(uint8_t*       buf,
                size_t         data_len,
                size_t         buf_capacity,
                const uint8_t  session_seed[2] = nullptr) noexcept;

    // Returns the byte offset at which real AEGS data starts in an inbound packet.
    size_t unwrap_offset() const noexcept { return header_size_; }

    Mode     mode()         const noexcept { return mode_; }
    size_t   header_size()  const noexcept { return header_size_; }
    uint32_t quic_version() const noexcept { return quic_version_; }

    void set_mode(Mode mode) noexcept;
    void set_quic_version(uint32_t version) noexcept { quic_version_ = version; }

private:
    Mode     mode_;
    size_t   header_size_;  // 0 for NONE, 24 for QUIC_INITIAL / HTTP3 / VERSION_NEGOTIATION
    uint32_t quic_version_; // 0 = dynamic selection
};

// Global free function helper for wrap_quic_initial
inline size_t wrap_quic_initial(uint8_t*       buf,
                                size_t         data_len,
                                size_t         buf_capacity,
                                const uint8_t  session_seed[2] = nullptr,
                                uint32_t       quic_version = 0) noexcept {
    return ProtocolMimicry::wrap_quic_initial(buf, data_len, buf_capacity, session_seed, quic_version);
}
