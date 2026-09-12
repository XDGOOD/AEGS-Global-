#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

// Protocol Constants
inline const std::string VER_MAGIC = "AG2\x01";
constexpr int AEGS_PBKDF2_ITERATIONS = 200000;
constexpr size_t BUFFER_SIZE = 64000;
constexpr size_t INTERNAL_BUF_SIZE = 65535;
constexpr size_t TAG_LEN = 16;
constexpr size_t FRAME_HDR = 2;
constexpr size_t PAD_MIN = 32;
constexpr size_t PAD_MAX = 256;

inline void compute_key_id(const std::string& token, uint8_t* kid_out, std::string& kid_hex_out) {
    uint8_t full[32];
    unsigned int dlen = 32;
    EVP_Digest(token.c_str(), token.length(), full, &dlen, EVP_sha256(), nullptr);
    std::memcpy(kid_out, full, 8);
    char hex[17];
    for (int i = 0; i < 8; ++i) sprintf(&hex[i * 2], "%02x", kid_out[i]);
    hex[16] = '\0';
    kid_hex_out = hex;
}

inline bool derive_master_key(const std::string& token, const std::string& salt, uint8_t* master_key_out) {
    return PKCS5_PBKDF2_HMAC(token.c_str(), static_cast<int>(token.length()),
                              reinterpret_cast<const unsigned char*>(salt.c_str()), static_cast<int>(salt.length()),
                              AEGS_PBKDF2_ITERATIONS, EVP_sha256(), 32, master_key_out) == 1;
}

inline bool hkdf_expand(const uint8_t* master_key, size_t master_key_len, const std::string& info, uint8_t* out, size_t out_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return false;
    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, reinterpret_cast<const unsigned char*>("aegis-v2-salt"), 13) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, master_key, static_cast<int>(master_key_len)) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, reinterpret_cast<const unsigned char*>(info.data()), static_cast<int>(info.size())) <= 0 ||
        EVP_PKEY_derive(pctx, out, &out_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);
    return true;
}

// RAII thread_local EVP_CIPHER_CTX holder to guarantee zero heap allocations on the packet hot path
struct ThreadLocalCipherCtx {
    EVP_CIPHER_CTX* ctx = nullptr;

    ThreadLocalCipherCtx() noexcept {
        ctx = EVP_CIPHER_CTX_new();
    }

    ~ThreadLocalCipherCtx() {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
            ctx = nullptr;
        }
    }

    ThreadLocalCipherCtx(const ThreadLocalCipherCtx&) = delete;
    ThreadLocalCipherCtx& operator=(const ThreadLocalCipherCtx&) = delete;
};

// AWG v3 Dynamic Header Masking (ChaCha20 Stream Cipher)
inline bool mask_unmask_header(const uint8_t* in, size_t len, const uint8_t* mask_key, const uint8_t* hdr_iv, uint8_t* out) {
    uint8_t full_iv[16] = {0};
    std::memcpy(full_iv + 4, hdr_iv, 12);

    thread_local ThreadLocalCipherCtx tl_ctx;
    EVP_CIPHER_CTX* ctx = tl_ctx.ctx;
    if (!ctx) return false;
    EVP_CIPHER_CTX_reset(ctx);

    int outlen = 0;
    if (EVP_CipherInit_ex(ctx, EVP_chacha20(), NULL, mask_key, full_iv, 1) != 1 ||
        EVP_CipherUpdate(ctx, out, &outlen, in, static_cast<int>(len)) != 1) {
        EVP_CIPHER_CTX_reset(ctx);
        return false;
    }
    int final_len = 0;
    EVP_CipherFinal_ex(ctx, out + outlen, &final_len);
    EVP_CIPHER_CTX_reset(ctx);
    return true;
}

inline bool chacha20_poly1305_encrypt(const uint8_t* pt, size_t pt_len, const uint8_t* key, const uint8_t* nonce,
                                      uint8_t* ct, size_t& ct_len, const uint8_t* aad = nullptr, size_t aad_len = 0) {
    thread_local ThreadLocalCipherCtx tl_ctx;
    EVP_CIPHER_CTX* ctx = tl_ctx.ctx;
    if (!ctx) return false;
    EVP_CIPHER_CTX_reset(ctx);

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_reset(ctx);
        return false;
    }
    int len = 0;
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, static_cast<int>(aad_len)) != 1) {
            EVP_CIPHER_CTX_reset(ctx);
            return false;
        }
    }
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, static_cast<int>(pt_len)) != 1) {
        EVP_CIPHER_CTX_reset(ctx);
        return false;
    }
    int total_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) {
        EVP_CIPHER_CTX_reset(ctx);
        return false;
    }
    total_len += len;
    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_reset(ctx);
        return false;
    }
    std::memcpy(ct + total_len, tag, 16);
    ct_len = total_len + 16;
    EVP_CIPHER_CTX_reset(ctx);
    return true;
}

inline bool chacha20_poly1305_decrypt(const uint8_t* ct, size_t ct_len, const uint8_t* key, const uint8_t* nonce,
                                      uint8_t* pt, size_t& pt_len, const uint8_t* aad = nullptr, size_t aad_len = 0) {
    if (ct_len < 16) return false;
    size_t c_len = ct_len - 16;
    const uint8_t* tag = ct + c_len;

    thread_local ThreadLocalCipherCtx tl_ctx;
    EVP_CIPHER_CTX* ctx = tl_ctx.ctx;
    if (!ctx) return false;
    EVP_CIPHER_CTX_reset(ctx);

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_reset(ctx);
        return false;
    }
    int len = 0;
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, static_cast<int>(aad_len)) != 1) {
            EVP_CIPHER_CTX_reset(ctx);
            return false;
        }
    }
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, static_cast<int>(c_len)) != 1) {
        EVP_CIPHER_CTX_reset(ctx);
        return false;
    }
    int total_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(tag)) != 1) {
        EVP_CIPHER_CTX_reset(ctx);
        return false;
    }
    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) <= 0) {
        EVP_CIPHER_CTX_reset(ctx);
        return false;
    }
    total_len += len;
    pt_len = total_len;
    EVP_CIPHER_CTX_reset(ctx);
    return true;
}
