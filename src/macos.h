#pragma once

#include "helpers.h"

#ifdef __APPLE__

#include <signal.h>
#include <spawn.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace crypto {
namespace macos {

struct executor {
    int kfd;
    std::atomic_bool stopped{ false };
    std::atomic_int jobs{ 0 };
    std::map<int, std::move_only_function<void(char *, size_t)>> read_callbacks;
    std::map<int, std::move_only_function<void()>> process_callbacks;

    executor() {
        kfd = kqueue();
        if (kfd == -1) {
            throw std::runtime_error{ "can create kqueue" };
        }
    }
    ~executor() {
        close(kfd);
    }
    void run() {
        while (!stopped && (jobs || !process_callbacks.empty())) {
            run_one();
        }
    }
    void run_one() {
        struct kevent ev {};
        if (kevent(kfd, 0, 0, &ev, 1, 0) == -1) {
            throw std::runtime_error{ "error kevent queue" };
        }
        if (auto it = process_callbacks.find(ev.ident); it != process_callbacks.end()) {
            it->second();
            process_callbacks.erase(it);
            return;
        }
        auto it = read_callbacks.find(ev.ident);
        char buffer[4096];
        while (1) {
            auto count = read(ev.ident, buffer, sizeof(buffer));
            if (count <= -1) {
                if (errno == EINTR) {
                    continue;
                }
                //perror("read");
                //exit(1);
                break;
            } else if (count == 0) {
                break;
            }
            if (it != read_callbacks.end()) {
                it->second(buffer, count);
            }
        }
    }

    void register_read_handle(auto &&fd, auto &&f) {
        struct kevent ev {};
        EV_SET(&ev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
        if (kevent(kfd, &ev, 1, 0, 0, 0) == -1) {
            throw std::runtime_error{ "error kevent queue" };
        }
        read_callbacks.emplace(fd, std::move(f));
    }
    void unregister_read_handle(auto &&fd) {
        read_callbacks.erase(fd);
    }
    void register_process(auto &&pid, auto &&f) {
        struct kevent ev {};
        EV_SET(&ev, pid, EVFILT_PROC, EV_ADD | EV_ENABLE, NOTE_EXIT, 0, 0);
        if (kevent(kfd, &ev, 1, 0, 0, 0) == -1) {
            if (errno == ESRCH) {
                f();
                return;
            }
            throw std::runtime_error{ "error kevent queue" };
        }
        process_callbacks.emplace(pid, std::move(f));
    }
};


struct endpoint {
    sockaddr_in addr{};
    int addrlen{ sizeof(addr) };

    endpoint() = default;
    endpoint(std::string_view s, auto &&port) {
        if (inet_pton(AF_INET, s.data(), (void *)&addr.sin_addr) != 1) {
            throw std::runtime_error{ "inet_pton() error" };
        }
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
    }
    endpoint(array<4> a, auto &&port) {
        memcpy((void *)&addr.sin_addr, a.data(), a.size());
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
    }
};

struct op_awaiter {
    io_callback cb;

    bool await_ready() const { return false; }
    void await_suspend(auto &&h) {
        cb.h = h;
    }
    void await_resume() const {
        if (cb.ec) {
            throw std::runtime_error{ std::format("error during op: {}: {}", cb.ec.value(), last_error_to_string(cb.ec.value())) };
        }
    }
};

struct socket {
    int s;
    socket(int s) : s{ s } {
    }
    socket(int af, int type, int protocol) {
        s = ::socket(af, type, protocol);
        if (s == -1) {
            throw std::runtime_error{ "cannot create socket" };
        }
    }
    ~socket() {
        close();
    }
    void close() {
        if (::close(s) == -1) {
            //
        }
    }
};

struct tcp_socket : socket {
    executor &ex;
    endpoint remote;

    tcp_socket(executor &e) : socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), ex{ e } {
        //e.register_handle(s);
    }

    awaitable<> async_connect(const endpoint &e) {
        remote = e;

        // ConnectEx requires a bound socket (can bind to INADDR_ANY, port 0)
        sockaddr_in localAddr;
        localAddr.sin_family = AF_INET;
        localAddr.sin_addr.s_addr = INADDR_ANY;
        localAddr.sin_port = 0;
        if (bind(s, &localAddr, sizeof(localAddr)) == -1) {
            throw std::runtime_error{ std::format("cannot bind") };
        }

        op_awaiter op;
        co_await op;
    }
    awaitable<> async_close() {
        close();
    }
    awaitable<size_t> async_send(std::span<bytes_concept> b) {
        co_return 0;
    }
    awaitable<size_t> async_send(std::vector<bytes_concept> &b) {
        co_return co_await async_send(std::span<bytes_concept>{b});
    }
    awaitable<size_t> async_send(bytes_concept b) {
        co_return co_await async_send(std::span<bytes_concept>{&b, 1});
    }
    awaitable<size_t> async_read(bytes_concept b) {
        co_return 0;
    }
    awaitable<std::string> async_read_some() {
        std::string buf;
        buf.resize(8192);
        auto n = co_await async_read_some(buf);
        buf.resize(n);
        co_return buf;
    }
    awaitable<size_t> async_read_some(bytes_concept b) {
        co_return 0;
    }
    const endpoint &remote_endpoint() const { return remote; }
};

struct udp_socket : socket {
    executor &ex;

    udp_socket(executor &e) : socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), ex{ e } {
        //ex.register_handle(s);
    }
    void open() {
    }
    awaitable<size_t> async_send_to(const endpoint &e, bytes_concept b) {
        co_return 0;
    }
    awaitable<size_t> async_receive_from(endpoint &e, bytes_concept b) {
        co_return 0;
    }
};

}

using endpoint = macos::endpoint;
using tcp_socket = macos::tcp_socket;
using udp_socket = macos::udp_socket;
using executor = macos::executor;

}

#endif
