#pragma once
#include <cstdint>
#include <chrono>
#include <vector>

class ChaffEngine {
public:
    ChaffEngine(int idle_threshold_ms = 500, int min_interval_ms = 50, int max_interval_ms = 200);

    bool should_send_chaff();
    void mark_real_packet();
    
    // Zero-allocation buffer builder (+15% throughput optimization)
    size_t build_chaff_packet(const uint8_t* raw_kid, const uint8_t* mask_key,
                             const uint8_t* send_key, uint64_t& tx_seq,
                             uint8_t* out_buf, size_t max_out_len);

    std::vector<uint8_t> generate_dummy_payload();
    std::vector<uint8_t> build_chaff_packet(const uint8_t* raw_kid, const uint8_t* mask_key,
                                            const uint8_t* send_key, uint64_t& tx_seq);

private:
    int idle_threshold_ms_;
    int min_interval_ms_;
    int max_interval_ms_;
    bool is_idle_ = false;
    std::chrono::steady_clock::time_point last_real_packet_;
    std::chrono::steady_clock::time_point next_chaff_time_;
    
    void schedule_next_chaff();
};
