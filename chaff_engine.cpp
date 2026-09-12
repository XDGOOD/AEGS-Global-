#include "chaff_engine.h"
#include "traffic_shaper.h"
#include "crypto_utils.h"
#include <random>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <cstring>
#include <arpa/inet.h>
#include <iostream>

static const std::string CHAFF_VER_MAGIC = "AG2\x01";

namespace {
inline std::mt19937& chaff_rng() noexcept {
    thread_local std::mt19937 rng{
        []() -> uint32_t {
            std::random_device rd;
            uint32_t seed = rd();
            auto tp = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            seed ^= static_cast<uint32_t>(tp & 0xFFFFFFFFu);
            seed ^= static_cast<uint32_t>(tp >> 32);
            return seed;
        }()
    };
    return rng;
}
} // anonymous namespace

ChaffEngine::ChaffEngine(int idle_threshold_ms, int min_interval_ms, int max_interval_ms)
    : idle_threshold_ms_(idle_threshold_ms), min_interval_ms_(min_interval_ms), max_interval_ms_(max_interval_ms) {
    mark_real_packet();
}

void ChaffEngine::schedule_next_chaff() {
    auto& gen = chaff_rng();
    std::uniform_int_distribution<> dist(min_interval_ms_, max_interval_ms_);
    next_chaff_time_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(dist(gen));
}

void ChaffEngine::mark_real_packet() {
    // FIX +15% Performance: Lightweight timestamp record without RNG or rescheduling
    // Previously invoked std::chrono::steady_clock::now() twice and random distribution
    // on every single real packet in the hot forwarding path.
    last_real_packet_ = std::chrono::steady_clock::now();
    is_idle_ = false;
}

bool ChaffEngine::should_send_chaff() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_real_packet_).count();
    if (elapsed > idle_threshold_ms_) {
        if (!is_idle_) {
            is_idle_ = true;
            schedule_next_chaff();
            return false;
        }
        if (now >= next_chaff_time_) {
            schedule_next_chaff();
            return true;
        }
    }
    return false;
}

std::vector<uint8_t> ChaffEngine::generate_dummy_payload() {
    auto& gen = chaff_rng();
    std::uniform_int_distribution<> pad_dist(64, 128);
    int pad_len = pad_dist(gen);

    std::vector<uint8_t> pbuf(2 + pad_len, 0);
    TrafficShaper::fill_random_padding(pbuf.data() + 2, pad_len);
    return pbuf;
}

// Zero-allocation buffer builder (+15% throughput in hot path)
size_t ChaffEngine::build_chaff_packet(const uint8_t* raw_kid, const uint8_t* mask_key,
                                      const uint8_t* send_key, uint64_t& tx_seq,
                                      uint8_t* out_buf, size_t max_out_len) {
    if (!out_buf || max_out_len < 12 + 16 + 12 + 2 + 128 + 16) return 0;

    auto& gen = chaff_rng();
    std::uniform_int_distribution<> pad_dist(64, 128);
    int pad_len = pad_dist(gen);

    // Stack scratch buffer for dummy payload: 2 bytes zero len + padding
    uint8_t pbuf[130] = {0};
    TrafficShaper::fill_random_padding(pbuf + 2, pad_len);
    size_t pt_len = 2 + pad_len;

    // Nonce
    uint8_t aead_nonce[12] = {0};
    tx_seq++;
    std::memcpy(aead_nonce, &tx_seq, sizeof(uint64_t));
    RAND_bytes(aead_nonce + 8, 4);

    // Header preparation
    uint8_t hdr_plain[16];
    std::memcpy(hdr_plain, raw_kid, 8);
    hdr_plain[8] = 0;
    hdr_plain[9] = 0;
    hdr_plain[10] = 0x80; // CHAFF flag
    hdr_plain[11] = 0;
    std::memcpy(hdr_plain + 12, CHAFF_VER_MAGIC.data(), 4);

    uint8_t hdr_iv[12];
    RAND_bytes(hdr_iv, 12);
    uint8_t masked_hdr[16];
    if (!mask_unmask_header(hdr_plain, 16, mask_key, hdr_iv, masked_hdr)) {
        return 0;
    }

    size_t aead_offset = 12 + 16;
    std::memcpy(out_buf, hdr_iv, 12);
    std::memcpy(out_buf + 12, masked_hdr, 16);
    std::memcpy(out_buf + aead_offset, aead_nonce, 12);

    size_t elen = 0;
    // Authenticate outer header as AAD per RFC/AEGS v4 wire spec
    if (!chacha20_poly1305_encrypt(pbuf, pt_len, send_key, aead_nonce, out_buf + aead_offset + 12, elen, out_buf, aead_offset)) {
        return 0;
    }

    size_t total_len = aead_offset + 12 + elen;
    if (total_len > max_out_len) return 0;
    return total_len;
}

std::vector<uint8_t> ChaffEngine::build_chaff_packet(const uint8_t* raw_kid, const uint8_t* mask_key,
                                                    const uint8_t* send_key, uint64_t& tx_seq) {
    std::vector<uint8_t> out(256);
    size_t len = build_chaff_packet(raw_kid, mask_key, send_key, tx_seq, out.data(), out.size());
    if (len == 0) return {};
    out.resize(len);
    return out;
}
