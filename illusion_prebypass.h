#pragma once
#include <vector>
#include <cstdint>
#include <arpa/inet.h>

class IllusionPreBypass {
public:
    static std::vector<uint8_t> generate_stun_binding();
    static std::vector<uint8_t> generate_quic_initial();
    static void send_illusion_sequence(int fd, const struct sockaddr_in& server_addr, const uint8_t* session_seed);
};
