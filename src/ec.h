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

point operator*(const bigint &m, const point &p) {
    if (m == 0) {
        return {p.ec};
    }
    point r0{p.ec};
    point r1 = p;
    for (int bit = mpz_sizeinbase(m, 2) - 1; bit >= 0; --bit) {
        if (mpz_tstbit(m, bit) == 0) {
            r1 = r0 + r1;
            r0 = r0.double_();
        } else {
            r0 = r0 + r1;
            r1 = r1.double_();
        }
    }
    return r0;
}

} // namespace crypto::ec
