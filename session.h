#pragma once
// ==============================================================================
// AEGS v6 "Titan" Global Edition -- Decomposed Session Model
// Architecture:
// 1. SessionIdentity: Immutable identity parameters (KeyID, SessionID, Generation)
// 2. SessionCrypto: Immutable RCU snapshot (MasterKey, MaskKey, SessionKeys, Handshake)
// 3. SessionRouting: Immutable RCU snapshot (Assigned IP, Client Addr, Server FD)
// 4. SessionCounters: Lock-free atomic sequence numbers & activity timestamps
// 5. SessionHandle: TOCTOU-safe reader epoch handle preventing concurrent recycle races
// ==============================================================================
#include <cstdint>
#include <memory>
#include <cstring>
#include <string>
#include <atomic>
#include <mutex>
#include <thread>
#include <netinet/in.h>
#include "network_security.h"
#include "handshake.h"

// ---------------------------------------------------------------------------
// 1. SessionIdentity: Immutable identity parameters
// ---------------------------------------------------------------------------
struct SessionIdentity {
    std::string           key_id_hex;
    uint64_t              key_id_raw = 0;
    std::atomic<uint64_t> session_id{0};
    std::atomic<uint64_t> generation{1}; // Lifecycle generation counter (Phase 18)
};

// ---------------------------------------------------------------------------
// 2. SessionCrypto: Cryptographic material & state (Immutable Snapshot)
// ---------------------------------------------------------------------------
struct SessionCrypto {
    uint8_t     master_key[32]{};
    uint8_t     mask_key[32]{};
    SessionKeys session_keys;       // ECDH-derived directional keys (recv/send)
    bool        v3_handshake_done = false;
};

// ---------------------------------------------------------------------------
// 3. SessionRouting: Endpoint and TUN address mapping (Immutable Snapshot)
// ---------------------------------------------------------------------------
struct SessionRouting {
    uint32_t           assigned_ip = 0; // Host byte order
    struct sockaddr_in client_addr{};
    bool               has_client = false;
    int                last_server_fd = -1;
    bool               uses_mimicry = false; // RFC 9000 QUIC DPI camouflage active
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
    SessionCounters  counters;
    AntiReplayFilter replay_filter;
    mutable std::mutex mu; // Protects replay filter & control mutations

    // TOCTOU / Concurrency Reader Tracking (P0-5)
    std::atomic<uint32_t> active_readers_{0};
    std::atomic<bool>     is_recycling_{false};

    // RCU / Copy-On-Write Crypto Snapshot (P0-6: Sole source of truth)
    std::shared_ptr<const SessionCrypto> crypto_snap_;
    mutable std::mutex                   crypto_mu_;

    // RCU / Copy-On-Write Routing Snapshot (P0-7: Lock-free packet path)
    std::shared_ptr<const SessionRouting> routing_snap_;
    mutable std::mutex                    routing_mu_;

    // Reference aliases for identity & atomic counters
    std::string&           key_id_hex;
    uint64_t&              key_id_raw;
    std::atomic<uint64_t>& session_id;
    std::atomic<uint64_t>& tx_seq;
    std::atomic<double>&   last_activity;

    std::shared_ptr<const SessionCrypto> get_crypto() const noexcept {
        return std::atomic_load(&crypto_snap_);
    }

    void set_crypto(const SessionCrypto& c) {
        std::lock_guard<std::mutex> lk(crypto_mu_);
        auto snap = std::make_shared<SessionCrypto>(c);
        std::atomic_store(&crypto_snap_, std::shared_ptr<const SessionCrypto>(snap));
    }

    std::shared_ptr<const SessionRouting> get_routing() const noexcept {
        return std::atomic_load(&routing_snap_);
    }

    void set_routing(const SessionRouting& r) {
        std::lock_guard<std::mutex> lk(routing_mu_);
        auto snap = std::make_shared<SessionRouting>(r);
        std::atomic_store(&routing_snap_, std::shared_ptr<const SessionRouting>(snap));
    }

    // Helper accessors
    const uint8_t* master_key() const noexcept {
        auto c = get_crypto();
        return c ? c->master_key : nullptr;
    }

    const uint8_t* mask_key() const noexcept {
        auto c = get_crypto();
        return c ? c->mask_key : nullptr;
    }

    bool v3_handshake_done() const noexcept {
        auto c = get_crypto();
        return c ? c->v3_handshake_done : false;
    }

    uint32_t assigned_ip() const noexcept {
        auto r = get_routing();
        return r ? r->assigned_ip : 0;
    }

    bool has_client() const noexcept {
        auto r = get_routing();
        return r ? r->has_client : false;
    }

    bool enter_reader() noexcept {
        if (is_recycling_.load(std::memory_order_acquire)) {
            return false;
        }
        active_readers_.fetch_add(1, std::memory_order_acquire);
        if (is_recycling_.load(std::memory_order_acquire)) {
            active_readers_.fetch_sub(1, std::memory_order_release);
            return false;
        }
        return true;
    }

    void exit_reader() noexcept {
        active_readers_.fetch_sub(1, std::memory_order_release);
    }

    Session()
        : key_id_hex(identity.key_id_hex),
          key_id_raw(identity.key_id_raw),
          session_id(identity.session_id),
          tx_seq(counters.tx_seq),
          last_activity(counters.last_activity)
    {
        SessionCrypto init_c{};
        set_crypto(init_c);
        SessionRouting init_r{};
        set_routing(init_r);
    }

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    bool check_replay(const uint8_t* n_bytes) {
        std::lock_guard<std::mutex> lk(mu);
        uint64_t seq = 0;
        std::memcpy(&seq, n_bytes, sizeof(uint64_t));
        return replay_filter.check_and_update(seq);
    }

    void recycle() noexcept {
        bool expected = false;
        if (!is_recycling_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            return;
        }
        identity.generation.fetch_add(1, std::memory_order_release);
        // Quiesce: wait for all in-flight readers in this generation to exit WITHOUT holding mu!
        while (active_readers_.load(std::memory_order_acquire) > 0) {
            std::this_thread::yield();
        }
        {
            // Atomically clear routing, crypto, and anti-replay under mutex only AFTER readers exit
            std::lock_guard<std::mutex> lk(mu);
            SessionRouting empty_routing{};
            set_routing(empty_routing);
            SessionCrypto empty_crypto{};
            set_crypto(empty_crypto);
            counters.tx_seq.store(0, std::memory_order_relaxed);
            replay_filter.reset();
        }
        is_recycling_.store(false, std::memory_order_release);
    }
};

// Safe generation-validated & reader-epoch session handle (P0-5)
struct SessionHandle {
    Session* ptr{nullptr};
    uint64_t gen{0};

    SessionHandle() = default;

    explicit SessionHandle(Session* s) noexcept {
        reset(s);
    }

    ~SessionHandle() noexcept {
        release();
    }

    SessionHandle(const SessionHandle& other) noexcept {
        reset(other.ptr);
    }

    SessionHandle& operator=(const SessionHandle& other) noexcept {
        if (this != &other) {
            reset(other.ptr);
        }
        return *this;
    }

    SessionHandle(SessionHandle&& other) noexcept : ptr(other.ptr), gen(other.gen) {
        other.ptr = nullptr;
        other.gen = 0;
    }

    SessionHandle& operator=(SessionHandle&& other) noexcept {
        if (this != &other) {
            release();
            ptr = other.ptr;
            gen = other.gen;
            other.ptr = nullptr;
            other.gen = 0;
        }
        return *this;
    }

    void reset(Session* s = nullptr) noexcept {
        release();
        if (s) {
            uint64_t g = s->identity.generation.load(std::memory_order_acquire);
            if (s->enter_reader()) {
                if (s->identity.generation.load(std::memory_order_acquire) == g) {
                    ptr = s;
                    gen = g;
                    return;
                }
                s->exit_reader();
            }
        }
        ptr = nullptr;
        gen = 0;
    }

    void release() noexcept {
        if (ptr) {
            ptr->exit_reader();
            ptr = nullptr;
            gen = 0;
        }
    }

    bool is_valid() const noexcept {
        return ptr != nullptr && ptr->identity.generation.load(std::memory_order_acquire) == gen;
    }

    Session* get() const noexcept {
        return ptr;
    }

    Session* operator->() const noexcept { return ptr; }
    Session& operator*() const noexcept { return *ptr; }
    operator Session*() const noexcept { return ptr; }
    explicit operator bool() const noexcept { return is_valid(); }
};
