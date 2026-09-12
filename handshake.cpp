#include "handshake.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <cstring>
#include <chrono>
#include <fstream>
#include <stdexcept>
#include <iostream>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <sys/stat.h>
#endif

// Helpers
static uint64_t htobe64_compat(uint64_t host_64) {
    uint64_t res;
    uint8_t* p = (uint8_t*)&res;
    p[0] = (uint8_t)(host_64 >> 56);
    p[1] = (uint8_t)(host_64 >> 48);
    p[2] = (uint8_t)(host_64 >> 40);
    p[3] = (uint8_t)(host_64 >> 32);
    p[4] = (uint8_t)(host_64 >> 24);
    p[5] = (uint8_t)(host_64 >> 16);
    p[6] = (uint8_t)(host_64 >> 8);
    p[7] = (uint8_t)(host_64);
    return res;
}

static uint64_t be64toh_compat(uint64_t big_endian_64) {
    const uint8_t* p = (const uint8_t*)&big_endian_64;
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

static EVP_PKEY* generate_x25519() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) return nullptr;
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr; // FIX MED-6: check return codes
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static std::vector<uint8_t> extract_x25519_pub(EVP_PKEY* pkey) {
    std::vector<uint8_t> pub(32);
    size_t len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) != 1) {
        return {}; // FIX MED-6: propagate error instead of silent garbage
    }
    return pub;
}

static std::vector<uint8_t> compute_mac(const uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len) {
    std::vector<uint8_t> mac(32);
    unsigned int len = 32;
    HMAC(EVP_sha256(), key, key_len, data, data_len, mac.data(), &len); // Fallback to HMAC-SHA256
    mac.resize(16); // truncate to 16 bytes
    return mac;
}

static std::vector<uint8_t> ecdh_derive(EVP_PKEY* priv, EVP_PKEY* pub) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) return {};
    if (EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, pub) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {}; // FIX MED-6: check return codes
    }
    size_t secret_len;
    EVP_PKEY_derive(ctx, NULL, &secret_len);
    std::vector<uint8_t> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return {};
    }
    EVP_PKEY_CTX_free(ctx);
    return secret;
}

static void hkdf_sha256(const std::vector<uint8_t>& secret, const uint8_t* salt, size_t salt_len, const char* info, uint8_t* out, size_t out_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len);
    EVP_PKEY_CTX_set1_hkdf_key(ctx, secret.data(), secret.size());
    EVP_PKEY_CTX_add1_hkdf_info(ctx, reinterpret_cast<const unsigned char*>(info), strlen(info));
    size_t olen = out_len;
    EVP_PKEY_derive(ctx, out, &olen);
    EVP_PKEY_CTX_free(ctx);
}

// ============================================================================
// Client
// ============================================================================

// FIX CRIT-1/CRIT-2: Constructor now takes master_key (secret known only to
// legitimate user) instead of server_pubkey (public, not a secret).
// Previously, passing nullptr here caused UB (memcpy from NULL).
HandshakeClient::HandshakeClient(const uint8_t key_id[8], const uint8_t master_key[32]) {
    memcpy(m_key_id, key_id, 8);
    memcpy(m_master_key, master_key, 32);
    m_ephemeral_pkey = generate_x25519();
}

HandshakeClient::~HandshakeClient() {
    if (m_ephemeral_pkey) EVP_PKEY_free(m_ephemeral_pkey);
}

std::vector<uint8_t> HandshakeClient::build_init() {
    if (!m_ephemeral_pkey) return {}; // FIX MED-6: keygen may have failed

    std::vector<uint8_t> packet(72, 0);
    packet[0] = 0x01; // type
    memcpy(&packet[8], m_key_id, 8);

    auto pub = extract_x25519_pub(m_ephemeral_pkey);
    if (pub.empty()) return {};
    memcpy(&packet[16], pub.data(), 32);

    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    uint64_t ts_be = htobe64_compat(now);
    memcpy(&packet[48], &ts_be, 8);

    // FIX CRIT-1: MAC is now HMAC(MasterKey, bytes[0:56]) — authenticates
    // that the sender knows the per-user secret (token-derived key).
    // Previously this used server_pubkey, which is public knowledge —
    // any attacker who knew the pubkey could forge a valid HANDSHAKE_INIT.
    auto mac = compute_mac(packet.data(), 56, m_master_key, 32);
    memcpy(&packet[56], mac.data(), 16);

    return packet;
}

// FIX Issue 3.1: Server response mutual authentication with MasterKey & AAD transcript.
// Verifies that HANDSHAKE_RESP was produced by the legitimate server holding MasterKey.
// Derives session keys using m_master_key as salt in HKDF, and passes bytes 0..47
// (Type, Reserved, SessionID, ServerEphemeralPublicKey) as AAD to ChaCha20-Poly1305.
bool HandshakeClient::process_resp(const uint8_t* resp, size_t len, SessionKeys& out) {
    // Response is now 80 bytes: 48 header + 16 ciphertext + 16 AEAD tag
    if (len < 80 || resp[0] != 0x02) return false;

    memcpy(&out.session_id, &resp[8], 8);

    EVP_PKEY* server_ephemeral = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, &resp[16], 32);
    if (!server_ephemeral) return false;

    auto shared_secret = ecdh_derive(m_ephemeral_pkey, server_ephemeral);
    EVP_PKEY_free(server_ephemeral);
    if (shared_secret.empty()) return false;

    // FIX Issue 3.1: Derive session keys using m_master_key (per-user secret) as salt
    // instead of public m_key_id. This ensures mutual authentication: an active MITM
    // without MasterKey cannot derive the correct keys or generate a valid AEAD tag.
    hkdf_sha256(shared_secret, m_master_key, 32, "aegs-c2s", out.send_key, 32);
    hkdf_sha256(shared_secret, m_master_key, 32, "aegs-s2c", out.recv_key, 32);

    // FIX Issue 12: Derive dedicated config_key for decrypting handshake response config.
    // Domain separation prevents ChaCha20-Poly1305 nonce reuse (nonce=0) with S2C data plane.
    uint8_t config_key[32];
    hkdf_sha256(shared_secret, m_master_key, 32, "aegs-cfg", config_key, 32);

    // Decrypt config with full AEAD tag verification, passing bytes 0..47 as AAD
    // to bind the entire handshake response transcript (type, session_id, server_epk)
    // to the Poly1305 authentication tag.
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    uint8_t nonce[12] = {0};
    int outlen = 0, final_len = 0;
    int unused = 0;
    uint8_t dec[16];

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, config_key, nonce) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &unused, resp, 48) != 1 ||
        EVP_DecryptUpdate(ctx, dec, &outlen, &resp[48], 16) != 1 ||
        // Set the expected AEAD tag (bytes 64..79 of response)
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                            const_cast<uint8_t*>(&resp[64])) != 1 ||
        // DecryptFinal verifies the Poly1305 tag — returns <= 0 on mismatch
        EVP_DecryptFinal_ex(ctx, dec + outlen, &final_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);

    out.assigned_ip = dec[0] | (dec[1] << 8) | (dec[2] << 16) | (dec[3] << 24);
    out.mtu = dec[4] | (dec[5] << 8);

    return true;
}

// ============================================================================
// Server
// ============================================================================

// FIX CRIT-1: Constructor now accepts master_key_map (key_id → 32-byte
// master key) for per-user MAC verification in process_init.
HandshakeServer::HandshakeServer(
    const std::unordered_map<uint64_t, std::string>& user_map,
    const std::unordered_map<uint64_t, std::vector<uint8_t>>& master_key_map)
    : m_user_map(user_map), m_master_keys(master_key_map),
      m_static_pkey(nullptr), m_last_prune_time(0) {
    load_or_generate_key();
}

HandshakeServer::~HandshakeServer() {
    if (m_static_pkey) EVP_PKEY_free(m_static_pkey);
    for (auto& kv : m_pending_clients) {
        EVP_PKEY_free(kv.second.client_ephemeral_pkey);
    }
}

void HandshakeServer::load_or_generate_key() {
    std::string path = "server_key.bin";
    std::ifstream is(path, std::ios::binary);
    if (is) {
        uint8_t priv[32];
        is.read((char*)priv, 32);
        m_static_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    } else {
        m_static_pkey = generate_x25519();
        if (!m_static_pkey) {
            std::cerr << "[AEGS] FATAL: Failed to generate server static key\n";
            return;
        }
        size_t len = 32;
        uint8_t priv[32];
        EVP_PKEY_get_raw_private_key(m_static_pkey, priv, &len);
        std::ofstream os(path, std::ios::binary);
        os.write((char*)priv, 32);
        os.close();
#ifndef _WIN32
        // FIX MED-3: Restrict private key permissions to owner only (0600)
        chmod(path.c_str(), 0600);
#endif
    }
}

std::vector<uint8_t> HandshakeServer::get_pubkey() const {
    return extract_x25519_pub(m_static_pkey);
}

// FIX Audit: Evict only timestamps older than 35,000 ms.
// Since valid timestamps must be within 30s (now - ts <= 30000), any timestamp
// older than 35s will be rejected by the timestamp validity check anyway.
// Retaining them for 35s completely closes the replay attack window.
void HandshakeServer::prune_timestamps(uint64_t now_ms) {
    if (now_ms - m_last_prune_time < 5000) return; // run every 5 seconds
    m_last_prune_time = now_ms;
    for (auto it = m_seen_timestamps.begin(); it != m_seen_timestamps.end(); ) {
        if (now_ms - it->second > 35000) {
            it = m_seen_timestamps.erase(it);
        } else {
            ++it;
        }
    }
}

// FIX CRIT-5: Evict pending handshake states older than PENDING_CLIENT_TTL_MS.
// Without this cleanup, an attacker flooding HANDSHAKE_INIT (each allocates an
// EVP_PKEY + map entry) causes unbounded memory growth → OOM.
void HandshakeServer::prune_pending(uint64_t now_ms) {
    for (auto it = m_pending_clients.begin(); it != m_pending_clients.end(); ) {
        if (now_ms - it->second.timestamp > PENDING_CLIENT_TTL_MS) {
            EVP_PKEY_free(it->second.client_ephemeral_pkey);
            it = m_pending_clients.erase(it);
        } else {
            ++it;
        }
    }
}

// FIX CRIT-1: MAC verification now uses user's MasterKey (secret), not
// server's public key (public knowledge). This ensures that only someone
// who possesses the token can generate a valid HANDSHAKE_INIT.
//
// FIX CRIT-5: Rejects if pending state exceeds MAX_PENDING_CLIENTS or
// seen timestamps exceed MAX_SEEN_TIMESTAMPS.
bool HandshakeServer::process_init(const uint8_t* init, size_t len, uint64_t& key_id_out) {
    if (len < 72 || init[0] != 0x01) return false;

    memcpy(&key_id_out, &init[8], 8);

    // FIX CRIT-1: Look up user's MasterKey by KeyID for MAC verification.
    // Old code: verified MAC with server's public key — any attacker who
    // knows the public key could pass this check without the token.
    auto mk_it = m_master_keys.find(key_id_out);
    if (mk_it == m_master_keys.end()) return false; // Unknown KeyID
    auto mac = compute_mac(init, 56, mk_it->second.data(), mk_it->second.size());
    if (CRYPTO_memcmp(mac.data(), &init[56], 16) != 0) return false;

    uint64_t ts;
    memcpy(&ts, &init[48], 8);
    ts = be64toh_compat(ts);

    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    if (now < ts || now - ts > 30000) return false; // 30 seconds

    std::lock_guard<std::mutex> lock(m_mutex);
    prune_timestamps(now);
    prune_pending(now); // FIX CRIT-5: clean stale pending states

    // FIX DoS Hardening: Instead of hard-rejecting when capacity is reached
    // (which allows an attacker flooding 1024 dummy packets to permanently lock
    // out legitimate users), evict the oldest pending entry (LRU eviction).
    if (m_pending_clients.size() >= MAX_PENDING_CLIENTS) {
        auto oldest_it = m_pending_clients.begin();
        for (auto it = m_pending_clients.begin(); it != m_pending_clients.end(); ++it) {
            if (it->second.timestamp < oldest_it->second.timestamp) {
                oldest_it = it;
            }
        }
        if (oldest_it != m_pending_clients.end()) {
            if (oldest_it->second.client_ephemeral_pkey) {
                EVP_PKEY_free(oldest_it->second.client_ephemeral_pkey);
            }
            m_pending_clients.erase(oldest_it);
        }
    }

    if (m_seen_timestamps.size() >= MAX_SEEN_TIMESTAMPS) {
        auto oldest_ts = m_seen_timestamps.begin();
        for (auto it = m_seen_timestamps.begin(); it != m_seen_timestamps.end(); ++it) {
            if (it->second < oldest_ts->second) {
                oldest_ts = it;
            }
        }
        if (oldest_ts != m_seen_timestamps.end()) {
            m_seen_timestamps.erase(oldest_ts);
        }
    }

    if (m_seen_timestamps.find(ts) != m_seen_timestamps.end()) return false;
    m_seen_timestamps[ts] = now;

    // Free any stale ephemeral key from a previous abandoned handshake for this key_id
    auto existing = m_pending_clients.find(key_id_out);
    if (existing != m_pending_clients.end() && existing->second.client_ephemeral_pkey) {
        EVP_PKEY_free(existing->second.client_ephemeral_pkey);
    }

    EVP_PKEY* client_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, &init[16], 32);
    if (!client_pub) return false; // FIX MED-6: check for failure
    m_pending_clients[key_id_out] = {client_pub, now};

    return true;
}

// FIX Issue 3.1: Full AEAD encryption of config with Poly1305 tag and MasterKey binding.
// Server derives session keys using the client's MasterKey as salt in HKDF, and
// authenticates the response header (bytes 0..47) via AEAD AAD.
// Response is 80 bytes: header(48) + ciphertext(16) + tag(16).
std::vector<uint8_t> HandshakeServer::build_resp(uint64_t key_id, uint32_t assigned_ip, uint16_t mtu, SessionKeys& out) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_pending_clients.find(key_id) == m_pending_clients.end()) return {};
    
    ClientState state = m_pending_clients[key_id];
    m_pending_clients.erase(key_id);

    auto mk_it = m_master_keys.find(key_id);
    if (mk_it == m_master_keys.end()) {
        EVP_PKEY_free(state.client_ephemeral_pkey);
        return {};
    }
    const uint8_t* master_key = mk_it->second.data();
    size_t master_key_len = mk_it->second.size();

    EVP_PKEY* server_ephemeral = generate_x25519();
    if (!server_ephemeral) {
        EVP_PKEY_free(state.client_ephemeral_pkey);
        return {};
    }
    auto shared_secret = ecdh_derive(server_ephemeral, state.client_ephemeral_pkey);
    EVP_PKEY_free(state.client_ephemeral_pkey);
    if (shared_secret.empty()) {
        EVP_PKEY_free(server_ephemeral);
        return {};
    }

    // FIX Issue 3.1: Derive session keys using MasterKey as salt in HKDF
    // instead of public key_id.
    hkdf_sha256(shared_secret, master_key, master_key_len, "aegs-c2s", out.recv_key, 32);
    hkdf_sha256(shared_secret, master_key, master_key_len, "aegs-s2c", out.send_key, 32);

    // FIX Issue 12: Derive dedicated config_key for encrypting handshake response config.
    // Domain separation prevents ChaCha20-Poly1305 nonce reuse (nonce=0) with S2C data plane.
    uint8_t config_key[32];
    hkdf_sha256(shared_secret, master_key, master_key_len, "aegs-cfg", config_key, 32);

    RAND_bytes((uint8_t*)&out.session_id, 8);
    out.assigned_ip = assigned_ip;
    out.mtu = mtu;

    // 80 bytes: type(1) + reserved(7) + session_id(8) + server_epk(32) +
    //           encrypted_config(16) + aead_tag(16)
    std::vector<uint8_t> resp(80, 0);
    resp[0] = 0x02;
    memcpy(&resp[8], &out.session_id, 8);
    
    auto pub = extract_x25519_pub(server_ephemeral);
    EVP_PKEY_free(server_ephemeral);
    if (pub.empty()) return {};
    memcpy(&resp[16], pub.data(), 32);

    // Encrypt config with full AEAD (EncryptUpdate + EncryptFinal + GET_TAG).
    // Associated Data (AAD) includes the 48-byte transcript header (type, reserved,
    // session_id, server_ephemeral_pub) so any tampering with the server ephemeral
    // key or session ID causes AEAD tag verification failure.
    uint8_t plain_config[16] = {0};
    plain_config[0] = assigned_ip & 0xFF;
    plain_config[1] = (assigned_ip >> 8) & 0xFF;
    plain_config[2] = (assigned_ip >> 16) & 0xFF;
    plain_config[3] = (assigned_ip >> 24) & 0xFF;
    plain_config[4] = mtu & 0xFF;
    plain_config[5] = (mtu >> 8) & 0xFF;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};
    uint8_t nonce[12] = {0};
    int outlen = 0, final_len = 0;
    int unused = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, config_key, nonce) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &unused, resp.data(), 48) != 1 ||
        EVP_EncryptUpdate(ctx, &resp[48], &outlen, plain_config, 16) != 1 ||
        EVP_EncryptFinal_ex(ctx, &resp[48 + outlen], &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    // Extract Poly1305 authentication tag (16 bytes) → stored at offset 64
    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    memcpy(&resp[48 + outlen + final_len], tag, 16);
    EVP_CIPHER_CTX_free(ctx);

    return resp;
}
