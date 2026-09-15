#pragma once
// ==============================================================================
// AEGS v6 "Titan" -- Session Resumption Token Manager (Fast & PFS Resume)
// Allows reconnect in <5ms instead of ~1s PBKDF2 handshake
// Fast Resume (0x04): Token verification with nonce-derived keys (0-RTT)
// PFS Resume (0x05): Token verification + fresh Ephemeral X25519 ECDH (Full PFS)
// ==============================================================================
#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <string>
#include <chrono>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

// Opcode constants
static constexpr uint8_t OP_FAST_RESUME_RESP  = 0x03;
static constexpr uint8_t OP_FAST_RESUME       = 0x04;
static constexpr uint8_t OP_PFS_RESUME        = 0x05;
static constexpr uint8_t OP_PFS_RESUME_RESP   = 0x06;

// 96 bytes on wire (sent in HANDSHAKE_RESP extension or 0x03 / 0x06 response)
#pragma pack(push, 1)
struct ResumptionToken {
    uint8_t nonce[32];      // random nonce
    uint8_t ciphertext[32]; // encrypted payload: session_id(8)+ip(4)+expiry_ms(8)+zeros(12)
    uint8_t tag[16];        // Poly1305 AEAD tag
    uint8_t key_id[8];      // User KeyID for O(1) server-side session lookup (authenticated as AAD)
    uint8_t reserved[8];    // zero-padded, future use
}; // total: 96 bytes
static_assert(sizeof(ResumptionToken) == 96, "ResumptionToken size mismatch");

// Wire layout for Opcode 0x05: Full PFS Resumption Request
struct PfsResumptionRequest {
    uint8_t opcode;                   // 0x05 (OP_PFS_RESUME)
    ResumptionToken token;            // 96 bytes
    uint8_t client_ephemeral_pub[32]; // 32 bytes X25519 public key
}; // total: 129 bytes
static_assert(sizeof(PfsResumptionRequest) == 129, "PfsResumptionRequest size mismatch");

// Wire layout for Opcode 0x06: Full PFS Resumption Response
struct PfsResumptionResponse {
    uint8_t opcode;                   // 0x06 (OP_PFS_RESUME_RESP)
    uint8_t server_ephemeral_pub[32]; // 32 bytes X25519 public key
    ResumptionToken new_token;        // 96 bytes fresh token for next resumption
    uint8_t auth_tag[16];             // 16 bytes HMAC-SHA256(master_key, bytes 0..128)
}; // total: 145 bytes
static_assert(sizeof(PfsResumptionResponse) == 145, "PfsResumptionResponse size mismatch");
#pragma pack(pop)

class ResumptionManager {
public:
    ResumptionManager() {
        // Generate per-boot secret: tokens from previous server instances
        // automatically fail verification even if still within TTL
        if (RAND_bytes(boot_secret_, 32) != 1) {
            throw std::runtime_error("OpenSSL RAND_bytes failed to generate boot_secret");
        }
    }

    // Issue a resumption token after successful handshake
    // Returns false if crypto fails
    bool issue(uint64_t session_id, uint32_t assigned_ip,
               const uint8_t master_key[32], ResumptionToken& tok_out,
               const uint8_t key_id[8] = nullptr) {
        uint8_t rkey[32];
        if (!derive_resumption_key(master_key, rkey)) return false;

        if (RAND_bytes(tok_out.nonce, 32) != 1) return false;

        if (key_id) {
            memcpy(tok_out.key_id, key_id, 8);
        } else {
            memset(tok_out.key_id, 0, 8);
        }
        memset(tok_out.reserved, 0, 8);

        uint8_t plain[32] = {0};
        memcpy(plain, &session_id, 8);
        memcpy(plain + 8, &assigned_ip, 4);
        uint64_t expiry = now_ms() + 180000ULL; // 3 minutes
        memcpy(plain + 12, &expiry, 8);

        uint8_t aad[48];
        memcpy(aad, tok_out.nonce, 32);
        memcpy(aad + 32, tok_out.key_id, 8);
        memcpy(aad + 40, tok_out.reserved, 8);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        int outlen = 0, flen = 0, aad_len = 0;
        bool ok = (
            EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
            EVP_EncryptInit_ex(ctx, NULL, NULL, rkey, tok_out.nonce) == 1 &&
            EVP_EncryptUpdate(ctx, NULL, &aad_len, aad, sizeof(aad)) == 1 &&
            EVP_EncryptUpdate(ctx, tok_out.ciphertext, &outlen, plain, 32) == 1 &&
            EVP_EncryptFinal_ex(ctx, tok_out.ciphertext + outlen, &flen) == 1
        );
        if (ok) {
            uint8_t tag[16];
            ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1;
            if (ok) memcpy(tok_out.tag, tag, 16);
        }
        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    // Verify and decode a token
    // Returns false if: expired, already used, AEAD fails, or crypto error
    bool verify(const ResumptionToken& tok, const uint8_t master_key[32],
                uint64_t& session_id_out, uint32_t& ip_out) {
        uint64_t cur_time = now_ms();

        // Anti-replay: fast pre-check before expensive HKDF/crypto
        std::string nonce_key(reinterpret_cast<const char*>(tok.nonce), 32);
        {
            std::lock_guard<std::mutex> lk(mu_);
            prune_expired_locked(cur_time);
            if (used_nonces_.find(nonce_key) != used_nonces_.end()) return false;
        }

        uint8_t rkey[32];
        if (!derive_resumption_key(master_key, rkey)) return false;

        uint8_t aad[48];
        memcpy(aad, tok.nonce, 32);
        memcpy(aad + 32, tok.key_id, 8);
        memcpy(aad + 40, tok.reserved, 8);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        uint8_t plain[32];
        int outlen = 0, flen = 0, aad_len = 0;
        uint8_t tag_copy[16];
        memcpy(tag_copy, tok.tag, 16);
        bool ok = (
            EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
            EVP_DecryptInit_ex(ctx, NULL, NULL, rkey, tok.nonce) == 1 &&
            EVP_DecryptUpdate(ctx, NULL, &aad_len, aad, sizeof(aad)) == 1 &&
            EVP_DecryptUpdate(ctx, plain, &outlen, tok.ciphertext, 32) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag_copy) == 1 &&
            EVP_DecryptFinal_ex(ctx, plain + outlen, &flen) > 0
        );
        EVP_CIPHER_CTX_free(ctx);
        if (!ok) return false;

        uint64_t expiry = 0;
        memcpy(&expiry, plain + 12, 8);
        if (cur_time > expiry) return false;

        // Atomic check-and-insert under lock: prevents R-02 TOCTOU race
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (used_nonces_.find(nonce_key) != used_nonces_.end()) return false;
            used_nonces_[nonce_key] = expiry;
        }

        memcpy(&session_id_out, plain, 8);
        memcpy(&ip_out, plain + 8, 4);
        return true;
    }

    // =========================================================================
    // Ephemeral X25519 & HKDF Helpers for Full PFS Resumption (Opcode 0x05/0x06)
    // =========================================================================
    static EVP_PKEY* generate_x25519_key() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
        if (!ctx) return nullptr;
        EVP_PKEY* pkey = NULL;
        if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }
        EVP_PKEY_CTX_free(ctx);
        return pkey;
    }

    static bool extract_x25519_pub(EVP_PKEY* pkey, uint8_t pub_out[32]) {
        size_t len = 32;
        return (EVP_PKEY_get_raw_public_key(pkey, pub_out, &len) == 1 && len == 32);
    }

    static bool compute_ecdh_shared(EVP_PKEY* priv, const uint8_t peer_pub[32], uint8_t shared_out[32]) {
        EVP_PKEY* peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, 32);
        if (!peer_pkey) return false;

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, NULL);
        if (!ctx) {
            EVP_PKEY_free(peer_pkey);
            return false;
        }

        bool ok = false;
        size_t secret_len = 32;
        if (EVP_PKEY_derive_init(ctx) > 0 &&
            EVP_PKEY_derive_set_peer(ctx, peer_pkey) > 0 &&
            EVP_PKEY_derive(ctx, shared_out, &secret_len) > 0 &&
            secret_len == 32) {
            ok = true;
        }
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_pkey);
        return ok;
    }

    static bool derive_pfs_keys(const uint8_t shared_secret[32],
                                const uint8_t master_key[32],
                                const uint8_t token_nonce[32],
                                uint8_t c2s_key_out[32],
                                uint8_t s2c_key_out[32]) {
        auto hex_encode = [](const uint8_t* data, size_t len) -> std::string {
            static const char* hexdigits = "0123456789abcdef";
            std::string out; out.reserve(len * 2);
            for (size_t i = 0; i < len; ++i) {
                out.push_back(hexdigits[data[i] >> 4]);
                out.push_back(hexdigits[data[i] & 0xF]);
            }
            return out;
        };
        std::string nonce_hex = hex_encode(token_nonce, 32);
        std::string c2s_info = "aegs-pfs-resume-" + nonce_hex + "-c2s";
        std::string s2c_info = "aegs-pfs-resume-" + nonce_hex + "-s2c";

        auto hkdf_derive = [&](const std::string& info, uint8_t out[32]) -> bool {
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
            if (!ctx) return false;
            size_t olen = 32;
            bool ok = (
                EVP_PKEY_derive_init(ctx) > 0 &&
                EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
                EVP_PKEY_CTX_set1_hkdf_salt(ctx, master_key, 32) > 0 &&
                EVP_PKEY_CTX_set1_hkdf_key(ctx, shared_secret, 32) > 0 &&
                EVP_PKEY_CTX_add1_hkdf_info(ctx, reinterpret_cast<const unsigned char*>(info.data()), info.size()) > 0 &&
                EVP_PKEY_derive(ctx, out, &olen) > 0 &&
                olen == 32
            );
            EVP_PKEY_CTX_free(ctx);
            return ok;
        };

        return hkdf_derive(c2s_info, c2s_key_out) && hkdf_derive(s2c_info, s2c_key_out);
    }

    static bool compute_pfs_resp_tag(const uint8_t* data, size_t len, const uint8_t master_key[32], uint8_t tag_out[16]) {
        unsigned int mac_len = 32;
        uint8_t full_mac[32];
        if (!HMAC(EVP_sha256(), master_key, 32, data, len, full_mac, &mac_len)) {
            return false;
        }
        std::memcpy(tag_out, full_mac, 16);
        return true;
    }

    static bool verify_pfs_resp_tag(const uint8_t* data, size_t len, const uint8_t master_key[32], const uint8_t tag[16]) {
        uint8_t expected[16];
        if (!compute_pfs_resp_tag(data, len, master_key, expected)) return false;
        return (CRYPTO_memcmp(tag, expected, 16) == 0);
    }

private:
    std::mutex mu_;
    uint8_t boot_secret_[32]{};
    std::unordered_map<std::string, uint64_t> used_nonces_;
    uint64_t last_prune_ms_ = 0;

    void prune_expired_locked(uint64_t now) {
        if (now - last_prune_ms_ < 10000 && used_nonces_.size() < 10000) return;
        last_prune_ms_ = now;
        for (auto it = used_nonces_.begin(); it != used_nonces_.end(); ) {
            if (now > it->second) {
                it = used_nonces_.erase(it);
            } else {
                ++it;
            }
        }
    }

    static uint64_t now_ms() {
        return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    bool derive_resumption_key(const uint8_t master_key[32], uint8_t out[32]) const {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
        if (!ctx) return false;
        static const unsigned char info[] = "aegs-v4-resumption-key";
        unsigned char salt[45];
        std::memcpy(salt, "aegis-v2-salt", 13);
        std::memcpy(salt + 13, boot_secret_, 32);
        size_t olen = 32;
        bool ok = (
            EVP_PKEY_derive_init(ctx) > 0 &&
            EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
            EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt)) > 0 &&
            EVP_PKEY_CTX_set1_hkdf_key(ctx, master_key, 32) > 0 &&
            EVP_PKEY_CTX_add1_hkdf_info(ctx, info, sizeof(info)-1) > 0 &&
            EVP_PKEY_derive(ctx, out, &olen) > 0
        );
        EVP_PKEY_CTX_free(ctx);
        return ok;
    }
};
