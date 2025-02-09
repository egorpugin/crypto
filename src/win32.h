// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2022-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#ifdef _WIN32

#include <string>
#include <stdexcept>

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#define WINAPI_CALL(x) if (!(x)) {throw ::win32::winapi_exception{#x};}

// we use this for easy command line building/bootstrapping
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "OleAut32.lib")
// for certs
#pragma comment(lib, "crypt.lib")

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
        if (!(h = CertOpenSystemStore(0, name.c_str()))) {
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

} // namespace win32

#endif
