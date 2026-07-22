#pragma once

#include "helpers.h"

#ifdef __linux__

#include <fcntl.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace crypto {
namespace linux {

struct executor {
    struct callback {
        int fd;
        bytes_concept b;
        size_t bytes{};
        void *data;
        std::error_code ec;
        std::coroutine_handle<> h;

        void f() {
            h();
        }

        int read() {
            while (1) {
                auto count = ::read(fd, b.data() + bytes, b.size() - bytes);
                if (count <= -1) {
                    if (errno == EINTR) {
                        continue;
                    }
                    //perror("read failed");
                    //exit(1);
                    return -1;
                } else if (count == 0) {
                    break;
                } else if (count == b.size()) {
                    bytes += count;
                    break;
                }
                bytes += count;
            }
            return bytes;
        }
        int write() {
            while (1) {
                auto count = ::write(fd, b.data() + bytes, b.size() - bytes);
                if (count <= -1) {
                    if (errno == EINTR) {
                        continue;
                    }
                    //perror("read failed");
                    //exit(1);
                    return -1;
                } else if (count == 0) {
                    break;
                } else if (count == b.size()) {
                    bytes += count;
                    break;
                }
                bytes += count;
            }
            return bytes;
        }
    };

    int efd;
    std::atomic_bool stopped{ false };
    std::atomic_int jobs{ 0 };
    std::map<int, std::move_only_function<void(char *, size_t)>> read_callbacks;
    std::map<int, std::move_only_function<void()>> process_callbacks;

    executor() {
        efd = epoll_create1(EPOLL_CLOEXEC);
        if (efd == -1) {
            throw std::runtime_error{ "cant create epoll" };
        }
    }
    ~executor() {
        //log_info("closing epoll");
        close(efd);
    }
    void run() {
        while (!stopped && (jobs || !process_callbacks.empty())) {
            run_one();
        }
    }
    void run_one() {
        epoll_event ev;
        if (epoll_wait(efd, &ev, 1, -1) == -1) {
            if (errno == EINTR) {
                return;
            }
            if (errno == EINVAL) {
                //log_info("epoll_wait");
                //return;
            }
            //throw std::runtime_error{"error epoll_wait"};
            perror("error epoll_wait");
            exit(1);
        }
        if (auto it = process_callbacks.find(ev.data.fd); it != process_callbacks.end()) {
            it->second();
            process_callbacks.erase(it);
            return;
        }
        auto &cb = *(callback*)ev.data.ptr;
        cb.f();
        unregister_job();
    }

    void co_spawn(auto &&coro, auto &&eh) {
        if (coro.p->eptr) {
            eh(coro.p->eptr);
        } else {
            coro.p->eh = eh;
        }
    }

    // rename to work?
    void register_job() {
        ++jobs;
    }
    void unregister_job() {
        --jobs;
    }
    void register_job(auto &&cb, auto &&flags) {
        epoll_event ev{};
        ev.events = flags | EPOLLONESHOT;
        ev.data.ptr = (void*)&cb;
        if (epoll_ctl(efd, EPOLL_CTL_ADD, cb.fd, &ev) == -1) {
            if (errno != EEXIST || epoll_ctl(efd, EPOLL_CTL_MOD, cb.fd, &ev) == -1) {
                throw std::runtime_error{ "error epoll_ctl: " + std::to_string(errno) };
            }
        }
        register_job();
    }
    void register_job_sock_in(auto &&cb) {
        register_job(cb, EPOLLIN);
    }
    void register_job_sock_out(auto &&cb) {
        register_job(cb, EPOLLOUT);
    }
    void register_job_sock_send(auto &&cb) {
        register_job_sock_out(cb);
    }
    void register_job_sock_recv(auto &&cb) {
        register_job_sock_in(cb);
    }

    void register_handle0(auto &&fd) {
        epoll_event ev{};
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = fd;
        if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) == -1) {
            throw std::runtime_error{ "error epoll_ctl: " + std::to_string(errno) };
        }
    }
    void register_read_handle(auto &&fd, auto &&f) {
        epoll_event ev{};
        ev.events = EPOLLIN;
        ev.data.fd = fd;
        if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) == -1) {
            throw std::runtime_error{ "error epoll_ctl: " + std::to_string(errno) };
        }
        read_callbacks.emplace(fd, std::move(f));
    }
    void unregister_read_handle(auto &&fd) {
        read_callbacks.erase(fd);
    }
    void register_process(auto &&fd, auto &&f) {
        process_callbacks.emplace(fd, std::move(f));

        epoll_event ev{};
        ev.events = EPOLLIN | EPOLLONESHOT;
        ev.data.fd = fd;
        if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) == -1) {
            throw std::runtime_error{ "error epoll_ctl: " + std::to_string(errno) };
        }
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

struct io_callback : executor::callback {
};

std::string last_error_to_string(auto e) {
    std::string r = std::to_string(e);
    return r;
}

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

    static int set_nonblocking(int fd) {
        int flags = fcntl(fd, F_GETFL, 0);
        return flags == -1 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    int set_nonblocking() {
        return set_nonblocking(s);
    }

    auto make_awaiter(bytes_concept b) {
        op_awaiter op;
        op.cb.fd = s;
        op.cb.b = b;
        return op;
    }
};

struct tcp_socket : socket {
    executor &ex;
    endpoint remote;

    tcp_socket(executor &e) : socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), ex{ e } {
        set_nonblocking();
        //ex.register_handle(s);
    }

    awaitable<> async_connect(const endpoint &e) {
        remote = e;

        // ConnectEx requires a bound socket (can bind to INADDR_ANY, port 0)
        sockaddr_in localAddr;
        localAddr.sin_family = AF_INET;
        localAddr.sin_addr.s_addr = INADDR_ANY;
        localAddr.sin_port = 0;
        if (bind(s, (sockaddr *)&localAddr, sizeof(localAddr)) == -1) {
            throw std::runtime_error{ std::format("cannot bind") };
        }

        if (connect(s, (struct sockaddr*)&remote.addr, remote.addrlen) == -1) {
            if (errno == EINPROGRESS) {
                op_awaiter op;
                op.cb.fd = s;
                ex.register_job_sock_send(op.cb);
                co_await op;
                co_return;
            }
            throw std::runtime_error{ std::format("cannot connect") };
        }

        op_awaiter op;
        //co_await op;
        co_return;
    }
    awaitable<> async_close() {
        close();
        co_return;
    }
    awaitable<size_t> async_send(std::span<bytes_concept> in) {
        size_t bytes_out{};
        for (auto &&b : in) {
            auto op = make_awaiter(b);
            int r = send(s, b.data(), b.size(), 0);
            if (r == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    ex.register_job_sock_send(op.cb);
                    co_await op;
                    op.cb.write();
                    co_return op.cb.bytes;
                }
                throw std::runtime_error{"error during send"};
            }
            if (r != b.size()) {
                throw std::runtime_error{"error during send - not enough size"};
            }
            bytes_out += r;
        }
        co_return bytes_out;
    }
    awaitable<size_t> async_send(std::vector<bytes_concept> &b) {
        co_return co_await async_send(std::span<bytes_concept>{b});
    }
    awaitable<size_t> async_send(bytes_concept b) {
        co_return co_await async_send(std::span<bytes_concept>{&b, 1});
    }
    awaitable<size_t> async_read(bytes_concept b) {
        auto op = make_awaiter(b);
        again:
        auto r = recv(s, b.data() + op.cb.bytes, b.size() - op.cb.bytes, 0);
        while (r == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                ex.register_job_sock_send(op.cb);
                co_await op;
                r = op.cb.read();
                if (r == -1) {
                    if (errno == EAGAIN) {
                        continue;
                    }
                    throw std::runtime_error{"error during recvfrom"};
                }
                co_return op.cb.bytes;
            }
            throw std::runtime_error{"error during recv"};
        }
        op.cb.bytes += r;
        if (op.cb.bytes < b.size()) {
            goto again;
            //throw std::runtime_error{"error during recv - not enough size"};
        }
        co_return op.cb.bytes;
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
        set_nonblocking();
        //ex.register_handle(s);
    }
    void open() {
    }
    awaitable<size_t> async_send_to(const endpoint &e, bytes_concept b) {
        auto op = make_awaiter(b);
        //ex.register_job_sock_send(op.cb);
        int r = sendto(s, b.data(), b.size(), 0, (struct sockaddr*)&e.addr, e.addrlen);
        if (r == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                ex.register_job_sock_send(op.cb);
                co_await op;
                op.cb.write();
                co_return op.cb.bytes;
            }
            throw std::runtime_error{"error during sendto"};
        }
        if (r != b.size()) {
            throw std::runtime_error{"error during sendto - not enough size"};
        }
        //co_await op;
        //op.cb.write();
        op.cb.bytes = r;
        co_return op.cb.bytes;
    }
    awaitable<size_t> async_receive_from(endpoint &e, bytes_concept b) {
        auto op = make_awaiter(b);
        //ex.register_job_sock_send(op.cb);
        int r = recvfrom(s, b.data(), b.size(), 0, (struct sockaddr*)&e.addr, (socklen_t*)&e.addrlen);
        while (r == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                ex.register_job_sock_recv(op.cb);
                co_await op;
                op.cb.read();
                co_return op.cb.bytes;
            }
            throw std::runtime_error{"error during recvfrom"};
        }
        if (r != b.size()) {
            //throw std::runtime_error{"error during sendto - not enough size"};
        }
        //co_await op;
        //op.cb.write();
        op.cb.bytes = r;
        co_return op.cb.bytes;
    }
};

}

using endpoint = linux::endpoint;
using tcp_socket = linux::tcp_socket;
using udp_socket = linux::udp_socket;
using executor = linux::executor;

}

#endif
