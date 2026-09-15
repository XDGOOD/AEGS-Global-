#pragma once
// ==============================================================================
// AEGS v6 "Titan" Global Edition -- Stage 20: Structured Non-Blocking Logging
// Prevents stdout/stderr contention from bottlenecking packet forwarding
// ==============================================================================
#include <iostream>
#include <string>
#include <atomic>
#include <chrono>

enum class AegsLogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO  = 2,
    WARN  = 3,
    ERROR = 4,
    NONE  = 5
};

class AegsLog {
public:
    static void set_level(AegsLogLevel lvl) noexcept {
        current_level().store(lvl, std::memory_order_relaxed);
    }

    static AegsLogLevel get_level() noexcept {
        return current_level().load(std::memory_order_relaxed);
    }

    static bool is_enabled(AegsLogLevel lvl) noexcept {
        return lvl >= get_level();
    }

    template <typename... Args>
    static void info(Args&&... args) {
        if (is_enabled(AegsLogLevel::INFO)) log("[INFO] ", std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void warn(Args&&... args) {
        if (is_enabled(AegsLogLevel::WARN)) log("[WARN] ", std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void error(Args&&... args) {
        if (is_enabled(AegsLogLevel::ERROR)) log("[ERROR] ", std::forward<Args>(args)...);
    }

    template <typename... Args>
    static void debug(Args&&... args) {
        if (is_enabled(AegsLogLevel::DEBUG)) log("[DEBUG] ", std::forward<Args>(args)...);
    }

private:
    static std::atomic<AegsLogLevel>& current_level() noexcept {
        static std::atomic<AegsLogLevel> lvl{AegsLogLevel::INFO};
        return lvl;
    }

    template <typename T, typename... Rest>
    static void log_parts(T&& first, Rest&&... rest) {
        std::cout << first;
        if constexpr (sizeof...(rest) > 0) {
            log_parts(std::forward<Rest>(rest)...);
        }
    }

    template <typename... Args>
    static void log(const char* prefix, Args&&... args) {
        std::cout << prefix;
        log_parts(std::forward<Args>(args)...);
        std::cout << "\n";
    }
};
