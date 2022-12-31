#pragma once

#include "bigint.h"

namespace crypto::ec {

// y^2 = x^3 + ax + b
struct simple {
    bigint a,b,p;
};

struct point {
    simple &ec;
    bigint x,y;

    bool operator==(const point &rhs) {
        return x == rhs.x && y == rhs.y;
    }
    bool operator==(const bigint &b) {
        return x == b && y == b;
    }
    point &operator=(const point &rhs) {
        x = rhs.x;
        y = rhs.y;
        return *this;
    }
    point &operator%=(const bigint &b) {
        x %= b;
        y %= b;
        return *this;
    }
    point double_() const {
        if (y == 0) {
            return point{ec};
        }
        bigint temp = y * 2;
        mpz_invert(temp, temp, ec.p);
        auto slope = ((x * x * 3 + ec.a) * temp) % ec.p;
        point r{ec};
        r.x = (slope * slope - x * 2) % ec.p;
        r.y = (slope * (x - r.x) - y) % ec.p;
        return r;
    }
    point operator+(point q) {
        *this %= ec.p;
        q %= ec.p;

        if (*this == 0) {
            return q;
        }
        if (q == 0) {
            return *this;
        }
        if (y == -q.y && x == q.x) {
            return {ec};
        }
        if (*this == q) {
            return double_();
        }

        bigint temp = (x - q.x) % ec.p;
        mpz_invert(temp, temp, ec.p);
        bigint slope = ((y - q.y) * temp) % ec.p;
        point r{ec};
        r.x = (slope * slope - x - q.x) % ec.p;
        r.y = (slope * (x - r.x) - y) % ec.p;
        return r;
    }
};
// can be time attacked!
point operator*(const bigint &m, const point &p) {
    point r{p.ec};

    if (m == 0) {
        return r;
    }
    if (mpz_tstbit(m, 0) == 1) {
        r = p;
    }
    auto no_of_bits = mpz_sizeinbase(m, 2);
    auto q = p;
    for (int loop = 1; loop < no_of_bits; ++loop) {
        q = q.double_();
        if (mpz_tstbit(m, loop)) {
            r = r + q;
        } else {
            // time attack is here!
            // in empty branch
        }
    }
    return r;
}

} // namespace crypto::ec
