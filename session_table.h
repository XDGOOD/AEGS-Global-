#pragma once
// ==============================================================================
// AEGS v4 "Pantheon" -- O(1) Session Table with RW-lock
// Replaces the O(n) linear scan over sessions in v3
// ==============================================================================
#include <cstdint>
#include <unordered_map>
#include <shared_mutex>
#include <functional>
#include <string>

// Forward declaration - Session struct is defined in server.cpp
struct Session;

class SessionTable {
public:
    SessionTable() = default;
    ~SessionTable() = default;

    // O(1) lookup - acquires shared (read) lock - multiple readers in parallel
    Session* find(uint64_t key_id_u64) const {
        std::shared_lock<std::shared_mutex> lk(mu_);
        auto it = table_.find(key_id_u64);
        return (it != table_.end()) ? it->second : nullptr;
    }

    // Also lookup by IP (for TUN -> session routing)
    Session* find_by_ip(uint32_t assigned_ip) const {
        std::shared_lock<std::shared_mutex> lk(mu_);
        auto it = ip_table_.find(assigned_ip);
        return (it != ip_table_.end()) ? it->second : nullptr;
    }

    void insert(uint64_t key_id_u64, Session* s) {
        std::unique_lock<std::shared_mutex> lk(mu_);
        table_[key_id_u64] = s;
    }

    void insert_ip(uint32_t assigned_ip, Session* s) {
        std::unique_lock<std::shared_mutex> lk(mu_);
        ip_table_[assigned_ip] = s;
    }

    void remove_ip(uint32_t assigned_ip) {
        std::unique_lock<std::shared_mutex> lk(mu_);
        ip_table_.erase(assigned_ip);
    }

    void remove(uint64_t key_id_u64) {
        std::unique_lock<std::shared_mutex> lk(mu_);
        table_.erase(key_id_u64);
    }

    // GC: iterate all sessions under exclusive lock
    void for_each(std::function<void(uint64_t, Session*)> fn) {
        std::shared_lock<std::shared_mutex> lk(mu_);
        for (auto& kv : table_) fn(kv.first, kv.second);
    }

    size_t size() const {
        std::shared_lock<std::shared_mutex> lk(mu_);
        return table_.size();
    }

    // Helper: convert 8-byte key_id hex string to uint64_t
    static uint64_t hex_to_u64(const std::string& hex) {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            unsigned int b = 0;
            sscanf(hex.c_str() + i * 2, "%02x", &b);
            reinterpret_cast<uint8_t*>(&v)[i] = static_cast<uint8_t>(b);
        }
        return v;
    }

    // Helper: convert raw 8-byte array to uint64_t
    static uint64_t bytes_to_u64(const uint8_t* bytes) {
        uint64_t v = 0;
        memcpy(&v, bytes, 8);
        return v;
    }

private:
    mutable std::shared_mutex mu_;
    std::unordered_map<uint64_t, Session*> table_;
    std::unordered_map<uint32_t, Session*> ip_table_;
};
