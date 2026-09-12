#pragma once
// ==============================================================================
// AEGS v5 "Pantheon" Global Edition -- Decomposed Session Model
// ==============================================================================
#include <cstdint>
#include <cstring>
#include <string>
#include <atomic>
#include <mutex>
#include <netinet/in.h>
#include "network_security.h"
#include "handshake.h"

// ---------------------------------------------------------------------------
// 1. SessionIdentity: Immutable identity parameters
// ---------------------------------------------------------------------------
struct SessionIdentity {
    std::string           key_id_hex;
    uint64_t              key_id_raw = 0;
    uint64_t              session_id = 0;
    std::atomic<uint64_t> generation{1}; // Lifecycle generation counter (Phase 18)
};

// ---------------------------------------------------------------------------
// 2. SessionCrypto: Cryptographic material & state
// ---------------------------------------------------------------------------
struct SessionCrypto {
    uint8_t     master_key[32]{};
    uint8_t     mask_key[32]{};
    SessionKeys session_keys;       // ECDH-derived directional keys (recv/send)
    bool        v3_handshake_done = false;
};

// ---------------------------------------------------------------------------
// 3. SessionRouting: Endpoint and TUN address mapping
// ---------------------------------------------------------------------------
struct SessionRouting {
    uint32_t           assigned_ip = 0; // Host byte order
    struct sockaddr_in client_addr{};
    bool               has_client = false;
    int                last_server_fd = -1;
};

// ---------------------------------------------------------------------------
// 4. SessionCounters: Hot-path atomic metrics & timestamps
// ---------------------------------------------------------------------------
struct SessionCounters {
    std::atomic<uint64_t> tx_seq{0};
    std::atomic<double>   last_activity{0.0};
    std::atomic<uint64_t> rx_packets{0};
    std::atomic<uint64_t> tx_packets{0};
    std::atomic<uint64_t> rx_bytes{0};
    std::atomic<uint64_t> tx_bytes{0};
};

// ---------------------------------------------------------------------------
// 5. Composite Session Object
// ---------------------------------------------------------------------------
struct Session {
    SessionIdentity  identity;
    SessionCrypto    crypto;
    SessionRouting   routing;
    SessionCounters  counters;
    AntiReplayFilter replay_filter;
    mutable std::mutex mu; // Protects non-atomic mutable updates (e.g. roaming / keys)

    // Convenient reference aliases for transparent zero-cost access
    std::string&           key_id_hex;
    uint64_t&              key_id_raw;
    uint64_t&              session_id;
    uint8_t*               master_key;
    uint8_t*               mask_key;
    SessionKeys&           session_keys;
    bool&                  v3_handshake_done;
    uint32_t&              assigned_ip;
    struct sockaddr_in&    client_addr;
    bool&                  has_client;
    int&                   last_server_fd;
    std::atomic<uint64_t>& tx_seq;
    std::atomic<double>&   last_activity;

    Session()
        : key_id_hex(identity.key_id_hex),
          key_id_raw(identity.key_id_raw),
          session_id(identity.session_id),
          master_key(crypto.master_key),
          mask_key(crypto.mask_key),
          session_keys(crypto.session_keys),
          v3_handshake_done(crypto.v3_handshake_done),
          assigned_ip(routing.assigned_ip),
          client_addr(routing.client_addr),
          has_client(routing.has_client),
          last_server_fd(routing.last_server_fd),
          tx_seq(counters.tx_seq),
          last_activity(counters.last_activity)
    {}

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    bool check_replay(const uint8_t* n_bytes) {
        std::lock_guard<std::mutex> lk(mu);
        uint64_t seq = 0;
        std::memcpy(&seq, n_bytes, sizeof(uint64_t));
        return replay_filter.check_and_update(seq);
    }

    void recycle() noexcept {
        identity.generation.fetch_add(1, std::memory_order_release);
        routing.has_client = false;
        routing.assigned_ip = 0;
        crypto.v3_handshake_done = false;
        counters.tx_seq.store(0, std::memory_order_relaxed);
        replay_filter.reset();
    }
};

// Safe generation-validated session handle (Phase 18)
struct SessionHandle {
    Session* ptr{nullptr};
    uint64_t gen{0};

    bool is_valid() const noexcept {
        return ptr != nullptr && ptr->identity.generation.load(std::memory_order_acquire) == gen;
    }

    Session* get() const noexcept {
        return is_valid() ? ptr : nullptr;
    }

    Session* operator->() const noexcept { return ptr; }
    explicit operator bool() const noexcept { return is_valid(); }
};
