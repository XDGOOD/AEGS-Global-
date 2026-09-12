#pragma once
#include <string>
#include <cstdio>

// Manages Linux iptables NAT and IP forwarding for AEGS v3 server
class NatManager {
public:
    // tun_iface: e.g. "aegs0", out_iface: e.g. "eth0", subnet: e.g. "10.8.0.0/24"
    NatManager(const std::string& tun_iface,
               const std::string& out_iface,
               const std::string& subnet);

    // Enable IP forwarding and set up MASQUERADE
    bool setup();

    // Remove iptables rules on shutdown
    void teardown();

    // Detect primary outbound network interface (reads /proc/net/route)
    static std::string detect_outbound_iface();

private:
    std::string tun_iface_;
    std::string out_iface_;
    std::string subnet_;
    bool active_ = false;

    int run_cmd(const std::string& cmd);
};
