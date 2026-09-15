#pragma once
// ==============================================================================
// AEGS v6 "Titan" Global Edition -- 64-Shard Partitioned Session Table
// Features:
// 1. 64 independent shards for KeyID and Endpoint lookups
// 2. Lock-free Copy-On-Write (COW/RCU) Route Table for TUN /32 IP lookups
//    (Eliminates all mutex contention on the TUN forwarding hot path)
// ==============================================================================
#include <cstdint>
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <atomic>
#include <functional>
#include <string>
#include <array>
#include <memory>
#include <cstring>
#include "session.h"

class SessionTable {
public:
    static constexpr size_t NUM_SHARDS = 64;
    using RouteMap = std::unordered_map<uint32_t, Session*>;

    SessionTable() {
        routes_ = std::make_shared<const RouteMap>();
    }

    ~SessionTable() {
        clear();
    }

    SessionTable(const SessionTable&) = delete;
    SessionTable& operator=(const SessionTable&) = delete;

    // -------------------------------------------------------------------------
    // Fast O(1) shard-indexed lookups
    // -------------------------------------------------------------------------
    SessionHandle find_by_key_id(uint64_t key_id) const {
        size_t s = shard_idx(key_id);
        std::shared_lock<std::shared_mutex> lk(shards_[s].mu);
        auto it = shards_[s].by_key_id.find(key_id);
        if (it != shards_[s].by_key_id.end() && it->second) {
            return SessionHandle(it->second);
        }
        return SessionHandle{};
    }

    SessionHandle find_by_key_id_hex(const std::string& hex) const {
        return find_by_key_id(hex_to_u64(hex));
    }

    // -------------------------------------------------------------------------
    // Lock-Free COW TUN Route Lookup (Phase 11): 0 locks on packet hot path
    // -------------------------------------------------------------------------
    SessionHandle find_by_assigned_ip(uint32_t ip) const noexcept {
        if (!ip) return SessionHandle{};
        std::shared_ptr<const RouteMap> snap = std::atomic_load(&routes_);
        auto it = snap->find(ip);
        if (it != snap->end() && it->second) {
            return SessionHandle(it->second);
        }
        return SessionHandle{};
    }

    SessionHandle find_by_endpoint(uint64_t ep_key) const {
        size_t s = shard_idx(ep_key);
        std::shared_lock<std::shared_mutex> lk(ep_shards_[s].mu);
        auto it = ep_shards_[s].by_endpoint.find(ep_key);
        if (it != ep_shards_[s].by_endpoint.end() && it->second) {
            return SessionHandle(it->second);
        }
        return SessionHandle{};
    }

    // -------------------------------------------------------------------------
    // Shard-isolated mutations
    // -------------------------------------------------------------------------
    void insert_session(Session* s) {
        if (!s) return;
        uint64_t kid = s->identity.key_id_raw;
        size_t shard = shard_idx(kid);
        std::unique_lock<std::shared_mutex> lk(shards_[shard].mu);
        shards_[shard].by_key_id[kid] = s;
    }

    // Control-plane updates: Copy-on-Write pointer swap
    void map_ip(uint32_t ip, Session* s) {
        if (!ip || !s) return;
        std::lock_guard<std::mutex> lk(route_write_mu_);
        auto old_snap = std::atomic_load(&routes_);
        auto new_snap = std::make_shared<RouteMap>(*old_snap);
        (*new_snap)[ip] = s;
        std::atomic_store(&routes_, std::shared_ptr<const RouteMap>(new_snap));
    }

    void unmap_ip(uint32_t ip) {
        if (!ip) return;
        std::lock_guard<std::mutex> lk(route_write_mu_);
        auto old_snap = std::atomic_load(&routes_);
        auto new_snap = std::make_shared<RouteMap>(*old_snap);
        new_snap->erase(ip);
        std::atomic_store(&routes_, std::shared_ptr<const RouteMap>(new_snap));
    }

    void update_endpoint(uint64_t ep_key, Session* s) {
        if (!s) return;
        size_t shard = shard_idx(ep_key);
        std::unique_lock<std::shared_mutex> lk(ep_shards_[shard].mu);
        ep_shards_[shard].by_endpoint[ep_key] = s;
    }

    void remove_endpoint(uint64_t ep_key) {
        size_t shard = shard_idx(ep_key);
        std::unique_lock<std::shared_mutex> lk(ep_shards_[shard].mu);
        ep_shards_[shard].by_endpoint.erase(ep_key);
    }

    void cleanup_idle_endpoints(double now, double timeout_sec) {
        for (size_t s = 0; s < NUM_SHARDS; ++s) {
            std::unique_lock<std::shared_mutex> lk(ep_shards_[s].mu);
            for (auto it = ep_shards_[s].by_endpoint.begin(); it != ep_shards_[s].by_endpoint.end(); ) {
                Session* sess = it->second;
                if (!sess || !sess->has_client() || (now - sess->counters.last_activity.load() > timeout_sec)) {
                    it = ep_shards_[s].by_endpoint.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }

    SessionHandle find_if(const std::function<bool(Session*)>& predicate) const {
        for (size_t s = 0; s < NUM_SHARDS; ++s) {
            std::vector<SessionHandle> candidates;
            {
                std::shared_lock<std::shared_mutex> lk(shards_[s].mu);
                candidates.reserve(shards_[s].by_key_id.size());
                for (const auto& kv : shards_[s].by_key_id) {
                    if (kv.second) {
                        SessionHandle h(kv.second);
                        if (h) candidates.push_back(std::move(h));
                    }
                }
            }
            for (auto& h : candidates) {
                if (h && predicate(h.get())) {
                    return h;
                }
            }
        }
        return SessionHandle{};
    }

    void for_each_session(std::function<void(Session*)> fn) {
        for (size_t s = 0; s < NUM_SHARDS; ++s) {
            std::shared_lock<std::shared_mutex> lk(shards_[s].mu);
            for (auto& kv : shards_[s].by_key_id) {
                fn(kv.second);
            }
        }
    }

    size_t total_sessions() const {
        size_t count = 0;
        for (size_t s = 0; s < NUM_SHARDS; ++s) {
            std::shared_lock<std::shared_mutex> lk(shards_[s].mu);
            count += shards_[s].by_key_id.size();
        }
        return count;
    }

    void clear() {
        // 1. Clear endpoints first to prevent new lookups during shutdown
        for (size_t s = 0; s < NUM_SHARDS; ++s) {
            std::unique_lock<std::shared_mutex> lk(ep_shards_[s].mu);
            ep_shards_[s].by_endpoint.clear();
        }
        // 2. Clear COW IP routes
        {
            std::lock_guard<std::mutex> lk(route_write_mu_);
            std::atomic_store(&routes_, std::make_shared<const RouteMap>());
        }
        // 3. Recycle & delete sessions (quiescing any in-flight readers first)
        for (size_t s = 0; s < NUM_SHARDS; ++s) {
            std::unique_lock<std::shared_mutex> lk(shards_[s].mu);
            for (auto& kv : shards_[s].by_key_id) {
                if (kv.second) {
                    kv.second->recycle();
                    delete kv.second;
                }
            }
            shards_[s].by_key_id.clear();
        }
    }

    static uint64_t hex_to_u64(const std::string& hex) {
        uint64_t v = 0;
        for (int i = 0; i < 8 && (i * 2 + 1) < (int)hex.size(); ++i) {
            unsigned int b = 0;
            std::sscanf(hex.c_str() + i * 2, "%02x", &b);
            reinterpret_cast<uint8_t*>(&v)[i] = static_cast<uint8_t>(b);
        }
        return v;
    }

    static std::string u64_to_hex(uint64_t v) {
        char hex[17];
        const uint8_t* b = reinterpret_cast<const uint8_t*>(&v);
        for (int i = 0; i < 8; ++i) sprintf(&hex[i * 2], "%02x", b[i]);
        hex[16] = '\0';
        return std::string(hex);
    }

private:
    static size_t shard_idx(uint64_t k) noexcept {
        k ^= k >> 30;
        k *= 0xbf58476d1ce4e5b9ULL;
        k ^= k >> 27;
        k *= 0x94d049bb133111ebULL;
        k ^= k >> 31;
        return static_cast<size_t>(k % NUM_SHARDS);
    }

    struct KeyShard {
        mutable std::shared_mutex mu;
        std::unordered_map<uint64_t, Session*> by_key_id;
    };

    struct EndpointShard {
        mutable std::shared_mutex mu;
        std::unordered_map<uint64_t, Session*> by_endpoint;
    };

    std::array<KeyShard, NUM_SHARDS>      shards_;
    std::array<EndpointShard, NUM_SHARDS> ep_shards_;

    // Lock-free route table snapshot pointer & writer mutex
    std::shared_ptr<const RouteMap>       routes_;
    std::mutex                            route_write_mu_;
};
