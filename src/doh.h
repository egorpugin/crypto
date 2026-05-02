#pragma once

#include "dns.h"
#include "http.h"

namespace crypto {

struct dns_over_http {
    struct server {
        std::string url;
    };
    std::vector<server> dns_servers;
    uint16_t query_id{};

    dns_over_http() = default;
    dns_over_http(std::initializer_list<const char *> list) {
        for (auto &&l : list) {
            dns_servers.emplace_back(l);
        }
    }

    auto query(auto &server, std::string_view domain, uint16_t type = dns_packet::qtype::A, uint16_t class_ = dns_packet::qclass::INTERNET) {
        constexpr auto udp_packet_max_size = 512;
        uint8_t bq[udp_packet_max_size]{};
        auto &q = *(dns_packet *)bq;
        q.h.id = query_id++;
        q.h.rd = 1; // some queries will fail without this
        q.set_question(domain, type, class_);

        // for GET use base64: ?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB
        http_client h{server.url};
        h.query_type = "POST"sv;
        h.headers.emplace_back("Accept"sv, "application/dns-message"sv);
        h.headers.emplace_back("Content-Type"sv, "application/dns-message"sv);
        h.headers.emplace_back("Content-Length"sv, std::format("{}", q.size()));
        h.body = bytes_concept{ bq, q.size() };
        h.run();
        if (h.m.code != 200) {
            throw std::runtime_error{"doh error"};
        }
        return dns_resolver::parse_response(q, *(dns_packet *)h.m.body.data());
    }
    auto query(std::string_view domain, uint16_t type = dns_packet::qtype::A, uint16_t class_ = dns_packet::qclass::INTERNET) {
        return query(dns_servers.at(0), domain, type, class_);
    }
};

auto &get_default_doh() {
    static dns_cache<dns_over_http> serv{
        "https://cloudflare-dns.com/dns-query",
        "https://wikimedia-dns.org/dns-query",
        "https://dns.google/dns-query",
        "https://mozilla.cloudflare-dns.com/dns-query",
        "https://dns.quad9.net/dns-query",
    };
    return serv;
}

}
