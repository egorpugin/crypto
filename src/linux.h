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

namespace crypto {
namespace linux {

struct executor {
    int efd;
    std::atomic_bool stopped{ false };
    std::atomic_int jobs{ 0 };
    std::map<int, std::move_only_function<void(char *, size_t)>> read_callbacks;
    std::map<int, std::move_only_function<void()>> process_callbacks;

    executor() {
        efd = epoll_create1(EPOLL_CLOEXEC);
        if (efd == -1) {
            throw std::runtime_error{ "can create epoll" };
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
        auto it = read_callbacks.find(ev.data.fd);
        char buffer[4096];
        while (1) {
            auto count = read(ev.data.fd, buffer, sizeof(buffer));
            if (count <= -1) {
                if (errno == EINTR) {
                    continue;
                }
                //perror("read failed");
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

}

using endpoint = linux::endpoint;
using tcp_socket = linux::tcp_socket;
using udp_socket = linux::udp_socket;
using executor = linux::executor;

}

#endif
