#pragma once
// ==============================================================================
// AEGS v4 "Pantheon" -- Port Hopping (Component 3: DPI bypass)
// ==============================================================================
// Server listens on N ports simultaneously. Client deterministically predicts
// the active port via HMAC-SHA256(session_key, floor(now/interval)).
// This makes passive DPI correlation much harder as the traffic port rotates
// every hop_interval_sec seconds in a session-key-dependent pattern.
// ==============================================================================

#include <cstdint>
#include <utility>
#include <vector>

class PortHopper {
public:
    // base_port:          lowest port in the hopping range (default 50001)
    // count:              number of ports in the range    (default 10)
    // hop_interval_sec:   how often the active port rotates (default 30 s)
    explicit PortHopper(uint16_t base_port        = 50001,
                        int      count            = 10,
                        uint32_t hop_interval_sec = 30) noexcept;

    // --- Server side --------------------------------------------------------
    // Returns all ports the server must bind (base_port .. base_port+count-1).
    std::vector<uint16_t> server_ports() const;

    // --- Client side --------------------------------------------------------
    // Compute the currently-active port using:
    //   epoch  = (uint64_t)(time(nullptr) / hop_interval_sec_)
    //   hmac   = HMAC-SHA256(session_key, epoch_be64)
    //   index  = load_le32(hmac[0..3]) % count_
    //   port   = base_port_ + index
    // session_key must point to exactly 32 bytes.
    uint16_t current_port(const uint8_t session_key[32]) const noexcept;

    // Returns {current_port, next_port} so the client can try both during
    // a boundary window (covers the brief transition period).
    std::pair<uint16_t, uint16_t>
    port_window(const uint8_t session_key[32]) const noexcept;

    // Server side: validates if received_port matches the expected port for session_key
    // in the current epoch or neighboring epochs (epoch - 1, epoch + 1) to absorb
    // network transit delay and clock skew across port hopping rotations.
    bool is_valid_port(const uint8_t session_key[32], uint16_t received_port) const noexcept;

    // Accessors
    uint16_t base_port()        const noexcept { return base_port_; }
    int      count()            const noexcept { return count_; }
    uint32_t hop_interval_sec() const noexcept { return hop_interval_sec_; }

private:
    uint16_t base_port_;
    int      count_;
    uint32_t hop_interval_sec_;

    // Internal helpers
    bool     compute_hmac(const uint8_t session_key[32],
                          uint64_t      epoch_be,
                          uint8_t       hmac_out[32]) const noexcept;
    uint16_t epoch_to_port(const uint8_t session_key[32],
                           uint64_t      epoch) const noexcept;
};
