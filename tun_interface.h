#pragma once

#include <string>
#include <cstdint>
#include <sys/types.h>

class TunInterface {
public:
    TunInterface(const std::string& iface_name, const std::string& ip_cidr, int mtu = 1400);
    ~TunInterface();

    bool open();
    void close();

    int fd() const;
    ssize_t read_packet(uint8_t* buf, size_t len);
    ssize_t write_packet(const uint8_t* buf, size_t len);

    bool add_route(const std::string& cidr);
    bool set_default_route();

    std::string ip() const;

private:
    int tun_fd_;
    std::string iface_name_;
    std::string ip_cidr_;
    std::string ip_;
    int mtu_;

    bool configure_interface();
    void parse_cidr(const std::string& cidr, std::string& ip, std::string& netmask);
};
