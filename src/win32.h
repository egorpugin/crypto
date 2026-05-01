// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#ifdef _WIN32

#include "helpers.h"

#include <string>
#include <stdexcept>

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#define WINAPI_CALL(x) if (!(x)) {throw ::crypto::win32::winapi_exception{#x};}

// we use this for easy command line building/bootstrapping
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "OleAut32.lib")
// for certs
#pragma comment(lib, "crypt.lib")

namespace crypto {
namespace win32 {

struct winapi_exception : std::runtime_error {
    using base = std::runtime_error;
    winapi_exception(const std::string &msg) : base{msg + ": " + get_last_error()} {
    }
    std::string get_last_error() const {
        auto code = GetLastError();

        LPVOID lpMsgBuf;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                      code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);
        std::string msg = (const char *)lpMsgBuf;
        LocalFree(lpMsgBuf);

        return "error code = " + std::to_string(code) + ": " + msg;
    }
};

struct handle {
    HANDLE h{INVALID_HANDLE_VALUE};

    handle() = default;
    handle(HANDLE h, auto &&err) : h{h} {
        if (h == INVALID_HANDLE_VALUE || !h) {
            err();
        }
    }
    handle(HANDLE h) : handle{h,[]{throw winapi_exception{"bad handle"};}} {
    }
    handle(const handle &) = delete;
    handle &operator=(const handle &) = delete;
    handle(handle &&rhs) noexcept {
        operator=(std::move(rhs));
    }
    handle &operator=(handle &&rhs) noexcept {
        this->~handle();
        h = rhs.h;
        rhs.h = INVALID_HANDLE_VALUE;
        return *this;
    }
    ~handle() {
        reset();
    }

    operator HANDLE() { return h; }
    operator HANDLE*() { return &h; }

    void reset() {
        CloseHandle(h);
        release();
    }
    void release() {
        h = INVALID_HANDLE_VALUE;
    }
};

struct certificate_store {
    struct iter {
        certificate_store &s;
        PCCERT_CONTEXT ctx{};
        iter(certificate_store &s) : s{s} {
            operator++();
        }
        bool operator==(int) const {return !ctx;}
        auto operator*() {
            return std::string_view{(const char*)ctx->pbCertEncoded, ctx->cbCertEncoded};
        }
        void operator++() {
            ctx = CertEnumCertificatesInStore(s.h, ctx);
        }
    };

    HANDLE h;

    certificate_store(const std::string &name) {
        if (!(h = CertOpenSystemStoreW(0, std::filesystem::path{name}.wstring().c_str()))) {
            throw std::runtime_error{"can't open cert store" + name};
        }
    }
    ~certificate_store() {
        CertCloseStore(h, 0);
    }
    auto begin() {
        return iter{*this};
    }
    auto end() {
        return 0;
    }
};

auto enum_certificate_store(auto &&name) {
    return certificate_store{name};
}

struct io_callback {
    OVERLAPPED o{};
    //std::move_only_function<void(io_callback &)> f;
    size_t bytes;
    void *data;
    std::error_code ec;
    std::coroutine_handle<> h;

    void operator()() {
        h();
    }
};

std::string last_error_to_string(auto e) {
    char buf[256]{};
    if (!FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, e,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buf, sizeof(buf), NULL)) {
        return std::format("{}: error during FormatMessageA({}): {}", e, e, GetLastError());
    }
    std::string r = buf;
    return r;
}

struct executor {
    handle port;
    std::atomic_bool stopped{ false };
    std::atomic_int jobs{};

    executor() {
        port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);
    }
    void stop() {
        stopped = true;
        PostQueuedCompletionStatus(port, 0, 0, 0);
    }
    void run() {
        while (!stopped && jobs != 0) {
            run_one();
        }
    }
    void run_one() {
        DWORD bytes;
        ULONG_PTR key;
        io_callback *o{ nullptr };
        if (!GetQueuedCompletionStatus(port, &bytes, &key, (LPOVERLAPPED *)&o, 1000)) {
            auto err = GetLastError();
            if (0) {
            } else if (err == ERROR_BROKEN_PIPE) {
            } else if (err == WAIT_TIMEOUT) {
            } else {
                o->ec = std::error_code{ (int)err, std::generic_category() };
                //throw std::runtime_error{ "cannot get io completion status" };
            }
        }
        if (!o) {
            return; // stop signal?
        }
        unregister_job();
        o->bytes = bytes;
        o->data = (void*)key;
        (*o)();
        //delete o;
    }

    void register_handle(auto &&h) { WINAPI_CALL(CreateIoCompletionPort((HANDLE)h, port, 0, 0)); }

    void cancel(auto &&h) {
        //WINAPI_CALL(CancelIo(h));
    }

    void co_spawn(auto &&coro, auto &&eh) {
        coro.p->eh = eh;
    }

    // rename to work?
    void register_job() {
        ++jobs;
    }
    void register_job(auto r, auto &&cmp, auto &&err, auto &&fmt) {
        register_job();
        if (cmp(r)) {
            r = err();
            if (r != WSA_IO_PENDING) {
                unregister_job();
                throw std::runtime_error{ fmt(r) };
            }
        }
    }
    void register_job_wsa0(auto r, auto &&cmp) {
        register_job(r,
            cmp,
            [](){return WSAGetLastError();},
            [](auto r){return std::format("wsa error: {}: {}", r, last_error_to_string(r));});
    }
    void register_job_wsa0(auto r) {
        register_job_wsa0(r, [](auto r) {return r == 0; });
    }
    void register_job_wsa(auto r) {
        register_job_wsa0(r, [](auto r) {return r != 0; });
    }
    void unregister_job() {
        --jobs;
    }
};

static inline struct wsa_startup {
    wsa_startup() {
        WSADATA data;
        if (WSAStartup(MAKEWORD(2, 2), &data)) {
            throw std::runtime_error{ "WSAStartup error" };
        }
    }
    ~wsa_startup() {
        WSACleanup();
    }
} ____auto_wsa_startup;

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

auto swap_for_wsa_buf(auto &b) {
    std::swap(b.p, (u8 *&)b.sz);
}

struct socket {
    SOCKET s;
    socket(SOCKET s) : s{s} {
    }
    socket(int af, int type, int protocol) {
        s = ::socket(af,type,protocol);
        if (s == -1) {
            throw std::runtime_error{"cannot create socket"};
        }
    }
    ~socket() {
        close();
    }
    void close() {
        if (closesocket(s) == SOCKET_ERROR) {
            //
        }
    }
};

struct tcp_socket : socket {
    executor &ex;
    endpoint remote;

    tcp_socket(executor &e) : socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), ex{e} {
        e.register_handle(s);
    }
    template <typename F>
    auto load_fn(GUID &&guid) {
        F fn;
        DWORD bytesReturned;
        if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER,
            &guid, sizeof(guid),
            &fn, sizeof(fn),
            &bytesReturned, NULL, NULL)) {
            throw std::runtime_error{ "WSAIoctl error" };
        }
        return fn;
    }
    awaitable<> async_connect(const endpoint &e) {
        remote = e;

        // ConnectEx requires a bound socket (can bind to INADDR_ANY, port 0)
        sockaddr_in localAddr;
        localAddr.sin_family = AF_INET;
        localAddr.sin_addr.s_addr = INADDR_ANY;
        localAddr.sin_port = 0;
        if (bind(s, (SOCKADDR *)&localAddr, sizeof(localAddr)) == -1) {
            throw std::runtime_error{ std::format("cannot bind") };
        }

        op_awaiter op;
        auto f = load_fn<LPFN_CONNECTEX>(WSAID_CONNECTEX);
        ex.register_job_wsa0(f(s, (sockaddr*)&e.addr, e.addrlen, 0, 0, 0, (LPOVERLAPPED)&op.cb));
        co_await op;
    }
    awaitable<> async_close() {
        op_awaiter op;
        auto f = load_fn<LPFN_DISCONNECTEX>(WSAID_DISCONNECTEX);
        ex.register_job_wsa0(f(s, (LPOVERLAPPED)&op.cb, 0, 0));
        co_await op;
    }
    awaitable<size_t> async_send(std::span<bytes_concept> b) {
        for (auto &&bb : b) {
            swap_for_wsa_buf(bb);
        }
        op_awaiter op;
        ex.register_job_wsa(WSASend(s, (LPWSABUF)b.data(), b.size(), nullptr, 0, (LPOVERLAPPED)&op.cb, nullptr));
        co_await op;
        co_return op.cb.bytes;
    }
    awaitable<size_t> async_send(std::vector<bytes_concept> &b) {
        co_return co_await async_send(std::span<bytes_concept>{b});
    }
    awaitable<size_t> async_send(bytes_concept b) {
        co_return co_await async_send(std::span<bytes_concept>{&b,1});
    }
    awaitable<size_t> async_read(bytes_concept b) {
        co_return co_await async_read_some(b, MSG_WAITALL);
    }
    awaitable<std::string> async_read_some() {
        std::string buf;
        buf.resize(8192);
        auto n = co_await async_read_some(buf);
        buf.resize(n);
        co_return buf;
    }
    awaitable<size_t> async_read_some(bytes_concept b, DWORD flags = 0) {
        swap_for_wsa_buf(b);
        op_awaiter op;
        ex.register_job_wsa(WSARecv(s, (LPWSABUF)&b, 1, nullptr, &flags, (LPOVERLAPPED)&op.cb, nullptr));
        co_await op;
        co_return op.cb.bytes;
    }
    const endpoint &remote_endpoint() const {return remote;}
};

struct udp_socket : socket {
    executor &ex;

    udp_socket(executor &e) : socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), ex{e} {
        ex.register_handle(s);
    }
    void open() {
    }
    awaitable<size_t> async_send_to(const endpoint &e, bytes_concept b) {
        swap_for_wsa_buf(b);
        op_awaiter op;
        ex.register_job_wsa(WSASendTo(s, (LPWSABUF)&b, 1, nullptr, 0, (sockaddr*)&e.addr, e.addrlen, (LPOVERLAPPED)&op.cb, nullptr));
        co_await op;
        co_return op.cb.bytes;
    }
    awaitable<size_t> async_receive_from(endpoint &e, bytes_concept b) {
        swap_for_wsa_buf(b);
        op_awaiter op;
        DWORD flags{};
        ex.register_job_wsa(WSARecvFrom(s, (LPWSABUF)&b, 1, nullptr, &flags, (sockaddr *)&e.addr, &e.addrlen, (LPOVERLAPPED)&op.cb, nullptr));
        co_await op;
        co_return op.cb.bytes;
    }
};

} // namespace win32

using endpoint = win32::endpoint;
using tcp_socket = win32::tcp_socket;
using udp_socket = win32::udp_socket;

} // namespace crypto

#endif
