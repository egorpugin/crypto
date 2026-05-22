#pragma once

#include "io.h"
#include "http.h"
#include "jwt.h"
#include "rsa.h"

namespace crypto {

// using service account
struct google_oauth {
    std::filesystem::path fn;
    std::string token_;
    std::chrono::steady_clock::time_point next_expire{};

    google_oauth(const std::filesystem::path &fn) : fn{ fn } {
    }
    std::string token() {
        if (std::chrono::steady_clock::now() > next_expire) {
            token_ = dl_token();
        }
        return token_;
    }
    std::string dl_token() {
        using namespace crypto;

        std::string client_id;
        std::string token_uri;

        auto jpk = json::parse(read_file(fn));
        token_uri = (std::string)jpk["token_uri"];
        client_id = (std::string)jpk["client_id"];

        auto pk = rsa::private_key::load_from_string_container(jpk["private_key"]);

        using cl = std::chrono::system_clock;
        auto now = cl::to_time_t(cl::now());

        jwt t;
        t.header["kid"] = jpk["private_key_id"];
        t.payload["iss"] = jpk["client_email"];
        t.payload["aud"] = jpk["token_uri"];
        t.payload["iat"] = now;
        t.payload["exp"] = now + 60 * 60;
        t.payload["scope"] = "https://www.googleapis.com/auth/spreadsheets";
        auto assertion = t.sign(jwt::rs<256>{}, pk);

        http_client h{ token_uri };
        h.query_type = "POST"sv;
        h.body = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion="s + assertion;
        h.headers.emplace_back("Content-Type"sv, "application/x-www-form-urlencoded"sv);
        h.headers.emplace_back("Content-Length"sv, std::format("{}", h.body.size()));
        h.run();
        auto &resp = h.m.body;
        if (h.m.code != 200) {
            try {
                auto j = json::parse(resp);
                throw std::runtime_error{ "cant get oauth token: "s +
                                         (std::string)json::parse(resp)["error"] };
            } catch (std::exception &e) {
                throw std::runtime_error{ "oauth request error: "s + token_uri + ": " + resp };
            }
        }
        auto j = json::parse(resp);
        int exp = j["expires_in"];
        next_expire = std::chrono::steady_clock::now() + std::chrono::seconds{ exp - 100 };
        return j["access_token"];
    }
};

}
