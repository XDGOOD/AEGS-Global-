#pragma once
// ==============================================================================
// AEGS v5 "Pantheon" Global Edition -- 64-Shard Lock-Free Partitioned Table
// Eliminates global lock contention across worker threads on the packet path
// ==============================================================================
#include <cstdint>
#include <unordered_map>
#include <shared_mutex>
#include <functional>
#include <string>
#include <array>
#include <memory>
#include <cstring>
#include "session.h"

class SessionTable {
public:
    static constexpr size_t NUM_SHARDS = 64;

    SessionTable() = default;
    ~SessionTable() {
        clear();
    }

    SessionTable(const SessionTable&) = delete;
    SessionTable& operator=(const SessionTable&) = delete;

    // -------------------------------------------------------------------------
    // Fast O(1) shard-indexed lookups
    // -------------------------------------------------------------------------
    Session* find_by_key_id(uint64_t key_id) const {
        size_t s = shard_idx(key_id);
        std::shared_lock<std::shared_mutex> lk(shards_[s].mu);
        auto it = shards_[s].by_key_id.find(key_id);
        return (it != shards_[s].by_key_id.end()) ? it->second : nullptr;
    }

    Session* find_by_key_id_hex(const std::string& hex) const {
        return find_by_key_id(hex_to_u64(hex));
    }

    Session* find_by_assigned_ip(uint32_t ip) const {
        size_t s = ip_shard_idx(ip);
        std::shared_lock<std::shared_mutex> lk(ip_shards_[s].mu);
        auto it = ip_shards_[s].by_ip.find(ip);
        return (it != ip_shards_[s].by_ip.end()) ? it->second : nullptr;
    }

    Session* find_by_endpoint(uint64_t ep_key) const {
        size_t s = shard_idx(ep_key);
        std::shared_lock<std::shared_mutex> lk(ep_shards_[s].mu);
        auto it = ep_shards_[s].by_endpoint.find(ep_key);
        return (it != ep_shards_[s].by_endpoint.end()) ? it->second : nullptr;
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

    void map_ip(uint32_t ip, Session* s) {
        if (!ip || !s) return;
        size_t shard = ip_shard_idx(ip);
        std::unique_lock<std::shared_mutex> lk(ip_shards_[shard].mu);
        ip_shards_[shard].by_ip[ip] = s;
    }

    void unmap_ip(uint32_t ip) {
        if (!ip) return;
        size_t shard = ip_shard_idx(ip);
        std::unique_lock<std::shared_mutex> lk(ip_shards_[shard].mu);
        ip_shards_[shard].by_ip.erase(ip);
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
                if (!sess || !sess->routing.has_client || (now - sess->counters.last_activity.load() > timeout_sec)) {
                    it = ep_shards_[s].by_endpoint.erase(it);
                } else {
                    ++it;
                }
            }
        }
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
        for (size_t s = 0; s < NUM_SHARDS; ++s) {
            std::unique_lock<std::shared_mutex> lk(shards_[s].mu);
            for (auto& kv : shards_[s].by_key_id) {
                delete kv.second;
            }
            shards_[s].by_key_id.clear();
        }
        for (size_t s = 0; s < NUM_SHARDS; ++s) {
            std::unique_lock<std::shared_mutex> lk(ip_shards_[s].mu);
            ip_shards_[s].by_ip.clear();
        }
        for (size_t s = 0; s < NUM_SHARDS; ++s) {
            std::unique_lock<std::shared_mutex> lk(ep_shards_[s].mu);
            ep_shards_[s].by_endpoint.clear();
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

    static size_t ip_shard_idx(uint32_t ip) noexcept {
        return shard_idx(static_cast<uint64_t>(ip));
    }

    struct KeyShard {
        mutable std::shared_mutex mu;
        std::unordered_map<uint64_t, Session*> by_key_id;
    };

    struct IpShard {
        mutable std::shared_mutex mu;
        std::unordered_map<uint32_t, Session*> by_ip;
    };

    struct EndpointShard {
        mutable std::shared_mutex mu;
        std::unordered_map<uint64_t, Session*> by_endpoint;
    };

    std::array<KeyShard, NUM_SHARDS>      shards_;
    std::array<IpShard, NUM_SHARDS>       ip_shards_;
    std::array<EndpointShard, NUM_SHARDS> ep_shards_;
};
