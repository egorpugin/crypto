#pragma once

#include "helpers.h"

#include <boost/asio.hpp>

#include <iostream>
#include <print>
#include <ranges>
#include <variant>

namespace crypto {

// https://www.ietf.org/rfc/rfc1035.txt
struct dns_packet {
    template <typename T> struct be {
        static_assert(sizeof(T) > 1, "must be greater than 1 byte");

        T value;

        be &operator=(const be &) = default;
        be &operator=(auto &&in) {
            value = in;
            swap();
            return *this;
        }
        be &operator++() {
            swap();
            ++value;
            swap();
            return *this;
        }
        operator auto() const {
            return std::byteswap(value);
        }

    private:
        void swap() {
            value = std::byteswap(value);
        }
    };
    // https://en.wikipedia.org/wiki/List_of_DNS_record_types
    struct type {
        enum {
            A       = 1,    // a host address
            NS,             // an authoritative name server
            MD,
            MF,
            CNAME,          // the canonical name for an alias
            SOA,            // marks the start of a zone of authority
            MB,             // a mailbox domain name (EXPERIMENTAL)
            MG,
            MR,
            NULL_,
            WKS,            // a well known service description
            PTR,            // a domain name pointer
            HINFO,
            MINFO,
            MX,             // mail exchange
            TXT,            // text strings

            AAAA = 28,      // ipv6

            HTTPS = 63,
        };
    };
    struct qtype : type {
        enum {
            AXFR    = 252,
            MAILB,
            MAILA,
            ALL_RECORDS = 255,

            URI = 256,
        };
    };
    struct class_ {
        enum {
            IN_ = 1,
            INTERNET = 1,
            CS,
            CH,
            HS,
        };
    };
    struct qclass : class_ {
        enum {
            ALL_RECORDS = 255,
        };
    };

    struct label {
        uint8_t length;
        uint8_t name[0];

        operator std::string_view() {
            return std::string_view{(char *)&name[0], (char *)&name[0] + length};
        }
    };
    struct pointer {
        be<uint16_t> value;

        auto offset() const {
            uint16_t v = value;
            v &= 0x3fff;
            return v;
        }
    };
    struct header {
        be<uint16_t> id;
        // BE order
        uint16_t rd     : 1;
        uint16_t tc     : 1;
        uint16_t aa     : 1;
        uint16_t opcode : 4;
        uint16_t qr     : 1;
        uint16_t rcode  : 4;
        uint16_t zeros  : 3; // empty field
        uint16_t ra     : 1;
        //
        be<uint16_t> qdcount;
        be<uint16_t> ancount;
        be<uint16_t> nscount;
        be<uint16_t> arcount;
    };
    struct question_type {
        struct end_type {
            be<uint16_t> qtype;
            be<uint16_t> qclass;
        };
        auto next_label() {
            auto p = (uint8_t *)this;
            while (*p) {
                p += 1 + *p;
            }
            return (label *)p;
        }
        void add_qname(auto &&qname) {
            auto p = next_label();
            p->length = qname.size();
            memcpy(p->name, qname.data(), p->length);
        }
        auto &labels_end(dns_packet &p) {
            return *(end_type *)p.labels((uint8_t *)this, [](auto){});
        }
        auto end(dns_packet &p) {
            auto qe = (uint8_t *)&labels_end(p);
            qe += sizeof(question_type::end_type);
            return (uint8_t *)qe;
        }
    };
    struct resource {
#pragma pack(push, 1)
        struct resource_end {
            be<uint16_t> type;
            be<uint16_t> class_;
            be<uint32_t> ttl;
            be<uint16_t> rdlength;
            uint8_t rdata[0]; // custom data
        };
#pragma pack(pop)
    };

    header h;
    // resource authority; // multiple
    // resource additional; // multiple

    auto &question() {
        auto p = (uint8_t *)&h;
        p += sizeof(h);
        return *(question_type *)p;
    }
    void set_question(const std::string &qname, uint16_t qtype, uint16_t qclass) {
        for (auto &&[b,e] : std::views::split(qname, "."sv)) {
            std::string_view sv{b, e};
            if (sv.size() > 64) {
                throw std::runtime_error{"bad label length (must be < 64)"};
            }
            question().add_qname(sv);
        }
        question().labels_end(*this).qtype = qtype;
        question().labels_end(*this).qclass = qclass;
        ++h.qdcount;
    }
    std::string string_at(auto &&start) {
        std::string s;
        for (auto &l : labels(start)) {
            s += l;
            s += ".";
        }
        if (!s.empty()) {
            s.pop_back();
        }
        return s;
    }
    std::vector<std::string_view> labels(auto &&start) {
        std::vector<std::string_view> r;
        start = labels(start, [&](auto sv) {r.push_back(sv);});
        return r;
    }
    uint8_t *labels(uint8_t *start, auto &&f) {
        again:
        if (*start >= 64) {
            auto &ptr = *(pointer*)start;
            auto labs = labels((uint8_t *)&h + ptr.offset());
            for (auto &&l : labs) {
                f(l);
            }
            start += 2;
        } else if (*start == 0) {
            // end
            ++start;
        } else {
            std::string_view v = *(label *)start;
            f(v);
            start += 1 + v.size();
            goto again;
        }
        return start;
    }

    struct base {
        uint32_t ttl;
    };
    struct a : base {
        static inline constexpr auto type = qtype::A;

        std::string name;
        array<4> address; // ipv4
    };
    struct cname : base {
        static inline constexpr auto type = qtype::CNAME;

        std::string name;
        std::string cname;
    };
    struct mx : base {
        static inline constexpr auto type = qtype::MX;

        be<uint16_t> preference;
        std::string exchange_host;
    };
    struct txt : base {
        static inline constexpr auto type = qtype::TXT;

        std::string data;
    };
    struct aaaa : base {
        static inline constexpr auto type = qtype::AAAA;

        std::string name;
        array<16> address; // ipv6
    };
    using record_type = std::variant<a, cname, mx, txt, aaaa>;
    auto answers() {
        std::vector<record_type> results;
        auto p = question().end(*this);
        uint16_t nres = h.ancount;
        while (nres--) {
            auto name = string_at(p);
            auto &res = *(resource::resource_end*)p;
            p += sizeof(res);
            // see rfc1035 for more types
            switch (res.type) {
            case qtype::A: {
                a r;
                r.ttl = res.ttl;
                r.name = std::move(name);
                memcpy(r.address.data(), p, r.address.size());
                p += res.rdlength;
                results.push_back(r);
                break;
            }
            case qtype::AAAA: {
                aaaa r;
                r.ttl = res.ttl;
                r.name = std::move(name);
                memcpy(r.address.data(), p, r.address.size());
                p += res.rdlength;
                results.push_back(r);
                break;
            }
            case qtype::CNAME: {
                cname r;
                r.ttl = res.ttl;
                r.name = std::move(name);
                r.cname = string_at(p);
                results.push_back(r);
                break;
            }
            case qtype::TXT: {
                txt r;
                r.ttl = res.ttl;
                auto len = *p;
                r.data.assign(p+1,p+1+len);
                p += res.rdlength;
                results.push_back(r);
                break;
            }
            case qtype::MX: {
                mx r;
                r.ttl = res.ttl;
                r.preference = *(uint16_t*)p;
                p += sizeof(r.preference);
                r.exchange_host = string_at(p);
                results.push_back(r);
                break;
            }
            default:
                throw std::runtime_error{"unimplemented"};
            }
        }
        return results;
    }

    size_t size() {
        return question().end(*this) - (uint8_t*)&h;
    }
};

struct dns_resolver {
    using results_type = std::vector<dns_packet::record_type>;
    struct server {
        std::string ip;
        uint16_t port{53};
    };
    std::vector<server> dns_servers;

    dns_resolver() = default;
    dns_resolver(std::initializer_list<const char *> list) {
        for (auto &&l : list) {
            dns_servers.emplace_back(l);
        }
    }

    auto query(auto &server, const std::string &domain, uint16_t type = dns_packet::qtype::A, uint16_t class_ = dns_packet::qclass::INTERNET) {
        // asio transport for now
        results_type results;
        boost::asio::io_context ctx;
        boost::asio::co_spawn(ctx, query_udp(results, server, domain, type, class_), [](auto eptr) {
            if (eptr) {
                std::rethrow_exception(eptr);
            }
        });
        ctx.run();
        return results;
    }
    auto query(const std::string &domain, uint16_t type = dns_packet::qtype::A, uint16_t class_ = dns_packet::qclass::INTERNET) {
        return query(dns_servers.at(0), domain, type, class_);
    }
    // return ips?
    auto resolve(const std::string &domain, uint16_t type = dns_packet::qtype::A, uint16_t class_ = dns_packet::qclass::INTERNET) {
        for (auto &&s : dns_servers) {
            for (auto &&r : query(s, domain, type, class_)) {
                if (auto p = std::get_if<dns_packet::a>(&r)) {
                    return p->address;
                }
            }
        }
        throw std::runtime_error{"server not found: " + domain};
    }

private:
    template <typename T = void> using task = boost::asio::awaitable<T>;

    task<> query_udp(auto &results, auto &server, const std::string &domain, uint16_t type, uint16_t class_) {
        namespace ip = boost::asio::ip;
        using namespace boost::asio::experimental::awaitable_operators;

        auto ex = co_await boost::asio::this_coro::executor;
        ip::udp::endpoint e(ip::make_address_v4(server.ip), server.port);
        ip::udp::socket s(ex);
        s.open(ip::udp::v4());
        constexpr auto udp_packet_max_size = 512;
        uint8_t buffer[udp_packet_max_size]{};
        auto &p = *(dns_packet *)buffer;
        //p.h.id = 123;
        p.h.rd = 1; // some queries will fail without this
        p.set_question(domain, type, class_);
        co_await s.async_send_to(boost::asio::buffer(buffer, p.size()), e, boost::asio::use_awaitable);
        boost::asio::deadline_timer dt{ex, boost::posix_time::seconds{2}};
        co_await (s.async_receive_from(boost::asio::buffer(buffer), e, boost::asio::use_awaitable) || dt.async_wait(boost::asio::use_awaitable));
        if (p.h.zeros || p.h.qr == 0) {
            co_return;
            //throw std::runtime_error{"bad response"};
        }
        enum {
            no_error,
            query_format_error,
            server_failure,
            domain_not_exists,
            function_not_implemented,
            server_refused_to_answer,
            name_should_not_exist_but_exists,
            rrset_should_not_exist_but_exists,
            server_not_authoritative_for_the_zone,
            name_not_in_zone,
        };
        switch (p.h.rcode) {
        case no_error:
            results = p.answers();
            break;
        case query_format_error:
            throw std::runtime_error{"bad request"};
        }
    }
};

struct dns_cache {
    struct query_type {
        std::string domain;
        int t;

        auto operator<=>(const query_type &) const = default;
    };
    struct results_type {
        std::chrono::system_clock::time_point last_query;
        std::chrono::seconds ttl{};
        dns_resolver::results_type results;

        bool outdated(auto &&now) const {return last_query + ttl < now;}
    };

    dns_resolver r;
    std::map<query_type, results_type> cache;

    dns_cache(std::initializer_list<const char *> list) : r{list} {
    }

    template <typename T>
    auto &query(const std::string &domain) {
        auto now = std::chrono::system_clock::now();
        query_type qt{domain, T::type};
        auto it = cache.find(qt);
        if (it == cache.end() || it->second.outdated(now)) {
            auto [it2,_] = cache.emplace(qt, results_type{});
            it = it2;
            auto &res = it->second;
            res.results = r.query(domain, T::type);
            res.last_query = now;
            if (!res.results.empty()) {
                visit(res.results[0], [&](auto &&v){res.ttl = std::chrono::seconds{v.ttl};});
            } else {
                res.ttl = 60s;
            }
        }
        return it->second.results;
    }
    template <typename T>
    auto query_one(const std::string &domain) {
        return std::get<T>(query<T>(domain).at(0));
    }
};

auto &get_default_dns() {
    static dns_cache serv{"178.208.90.175", "8.8.8.8", "8.8.4.4", "1.1.1.1"};
    return serv;
}

}
