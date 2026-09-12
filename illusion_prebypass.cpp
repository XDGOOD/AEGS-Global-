#include "illusion_prebypass.h"
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <random>
#include <chrono>
#include <cstring>
#include <openssl/rand.h>

// IEEE 802.3 CRC-32 algorithm (polynomial 0xEDB88320) for RFC 5389 STUN FINGERPRINT
static uint32_t stun_crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc = crc >> 1;
        }
    }
    return crc ^ 0xFFFFFFFF;
}

std::vector<uint8_t> IllusionPreBypass::generate_stun_binding() {
    // RFC 5389 compliant STUN Binding Request with USERNAME and FINGERPRINT attributes.
    // Real WebRTC / ICE clients include these attributes; bare 20-byte requests are anomalous.
    // Total size: 20-byte header + 12-byte USERNAME + 8-byte FINGERPRINT = 40 bytes.
    std::vector<uint8_t> pkt(40, 0);
    // 0x0001 Binding Request
    pkt[0] = 0x00;
    pkt[1] = 0x01;
    // Length of attributes: 20 bytes (0x0014)
    pkt[2] = 0x00;
    pkt[3] = 0x14;
    // Magic Cookie: 0x2112A442
    pkt[4] = 0x21;
    pkt[5] = 0x12;
    pkt[6] = 0xA4;
    pkt[7] = 0x42;
    // Transaction ID: 12 random bytes
    RAND_bytes(&pkt[8], 12);

    // Attribute 1: USERNAME (0x0006), Length: 8 bytes (simulating WebRTC ICE ufrag)
    pkt[20] = 0x00;
    pkt[21] = 0x06;
    pkt[22] = 0x00;
    pkt[23] = 0x08;
    static const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint8_t rand_bytes[8];
    RAND_bytes(rand_bytes, 8);
    for (int i = 0; i < 8; ++i) {
        pkt[24 + i] = charset[rand_bytes[i] % (sizeof(charset) - 1)];
    }

    // Attribute 2: FINGERPRINT (0x8028), Length: 4 bytes
    pkt[32] = 0x80;
    pkt[33] = 0x28;
    pkt[34] = 0x00;
    pkt[35] = 0x04;
    // RFC 5389 §15.5: CRC-32 over STUN message up to (not including) FINGERPRINT ^ 0x5354554E
    uint32_t crc = stun_crc32(pkt.data(), 32);
    uint32_t fp = crc ^ 0x5354554E;
    pkt[36] = static_cast<uint8_t>((fp >> 24) & 0xFF);
    pkt[37] = static_cast<uint8_t>((fp >> 16) & 0xFF);
    pkt[38] = static_cast<uint8_t>((fp >> 8) & 0xFF);
    pkt[39] = static_cast<uint8_t>(fp & 0xFF);

    return pkt;
}

std::vector<uint8_t> IllusionPreBypass::generate_quic_initial() {
    // RFC 9000 QUIC Initial packet (minimum MTU 1200 bytes)
    std::vector<uint8_t> pkt(1200, 0);
    // 0xC3: Long header, type 0x00 (Initial), 4-byte packet number (0x03)
    pkt[0] = 0xC3;
    // Version 1 (RFC 9000)
    pkt[1] = 0x00;
    pkt[2] = 0x00;
    pkt[3] = 0x00;
    pkt[4] = 0x01;
    
    // DCID length 8
    pkt[5] = 8;
    RAND_bytes(&pkt[6], 8);
    // SCID length 8
    pkt[14] = 8;
    RAND_bytes(&pkt[15], 8);
    
    // Token length = 0 (varint 0x00)
    pkt[23] = 0;

    // Length: RFC 9000 2-byte varint encoding of (Packet Number [4] + Payload [1170] = 1174 bytes)
    // 1174 = 0x0496. With 2-byte varint prefix 0x4000: 0x4496.
    uint16_t rem = static_cast<uint16_t>(pkt.size() - 26); // 1200 - 26 = 1174 (0x0496)
    pkt[24] = static_cast<uint8_t>(0x40 | ((rem >> 8) & 0x3F)); // 0x44
    pkt[25] = static_cast<uint8_t>(rem & 0xFF);                  // 0x96
    
    // Packet Number 4 bytes
    RAND_bytes(&pkt[26], 4);
    
    // Payload & AEAD auth tag simulation (1170 bytes)
    RAND_bytes(&pkt[30], rem - 4);
    return pkt;
}

void IllusionPreBypass::send_illusion_sequence(int fd, const struct sockaddr_in& server_addr, const uint8_t* session_seed) {
    (void)session_seed;
    std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<int> count_dist(1, 3);
    int count = count_dist(rng);

    for (int i = 0; i < count; ++i) {
        std::uniform_int_distribution<int> type_dist(0, 1);
        int type = type_dist(rng);
        std::vector<uint8_t> pkt;
        if (type == 0) {
            pkt = generate_stun_binding();
        } else {
            pkt = generate_quic_initial();
        }
        sendto(fd, (const char*)pkt.data(), pkt.size(), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

        // Short non-blocking poll/recvfrom to drain any server/blackhole response
        // and create realistic RTT timing on the wire for stateful DPI tracking.
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int poll_timeout_ms = 25 + (rng() % 35); // 25-60ms realistic network RTT
        int pr = poll(&pfd, 1, poll_timeout_ms);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            uint8_t drain_buf[2048];
            sockaddr_in from_addr{};
            socklen_t from_len = sizeof(from_addr);
            recvfrom(fd, (char*)drain_buf, sizeof(drain_buf), 0, (struct sockaddr*)&from_addr, &from_len);
        }
    }
}

