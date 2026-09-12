#pragma once
// ==============================================================================
// AEGS v5 "Pantheon" Global Edition -- Safe Direct Process Execution Helper
// Eliminates std::system() and subshell (/bin/sh -c) invocation in privileged code
// ==============================================================================

#include <string>
#include <vector>
#include <iostream>
#include <cctype>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#endif

inline int safe_exec(const std::string& cmd_str) noexcept {
    if (cmd_str.empty()) return 0;

    // Parse command line into arguments without invoking a shell
    std::vector<std::string> tokens;
    std::string cur;
    bool in_quotes = false;
    bool suppress_output = false;

    for (size_t i = 0; i < cmd_str.size(); ++i) {
        char c = cmd_str[i];
        if (c == '"' || c == 0x27) {
            in_quotes = !in_quotes;
        } else if (std::isspace(static_cast<unsigned char>(c)) && !in_quotes) {
            if (!cur.empty()) {
                if (cur == ">/dev/null" || cur == "2>&1") {
                    suppress_output = true;
                } else {
                    tokens.push_back(cur);
                }
                cur.clear();
            }
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) {
        if (cur == ">/dev/null" || cur == "2>&1") {
            suppress_output = true;
        } else {
            tokens.push_back(cur);
        }
    }

    if (tokens.empty()) return 0;

#ifdef _WIN32
    // Windows compatibility: safely simulate iptables/ip6tables/ip commands as successful
    if (tokens[0] == "iptables" || tokens[0] == "ip6tables" || tokens[0] == "ip") {
        return 0;
    }
    std::vector<const char*> argv;
    argv.reserve(tokens.size() + 1);
    for (const auto& t : tokens) argv.push_back(t.c_str());
    argv.push_back(nullptr);
    intptr_t ret = _spawnvp(_P_WAIT, argv[0], (char* const*)argv.data());
    return (ret == -1) ? -1 : static_cast<int>(ret);
#else
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    } else if (pid == 0) {
        // Child: optionally redirect stdout/stderr if command had redirection
        if (suppress_output) {
            int null_fd = open("/dev/null", O_WRONLY);
            if (null_fd >= 0) {
                dup2(null_fd, STDOUT_FILENO);
                dup2(null_fd, STDERR_FILENO);
                close(null_fd);
            }
        }
        std::vector<char*> argv;
        argv.reserve(tokens.size() + 1);
        for (auto& t : tokens) argv.push_back(const_cast<char*>(t.c_str()));
        argv.push_back(nullptr);

        execvp(argv[0], argv.data());
        _exit(127); // exec failed
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
#endif
}
