#pragma once

#include "bigint.h"

namespace crypto::ec {

// y^2 = x^3 + ax + b
struct simple {
    bigint a,b,p;
};

struct point {
    simple &ec;
    bigint x{0u},y{0u};

    bool operator==(const point &rhs) const {
        return x == rhs.x && y == rhs.y;
    }
    bool operator==(const bigint &b) const {
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
        bigint temp = y * 2u;
        temp %= ec.p;
        mpz_invert(temp, temp, ec.p);
        bigint slope{0u};
        slope = ((x * x * 3u + ec.a) * temp);
        slope %= ec.p;
        //slope = ((3 * x * x + ec.a) / (2 * y)) % ec.p;
        point r{ec};
        r.x = (slope * slope - x * 2u);
        r.x %= ec.p;
        r.y = (slope * (x - r.x) - y);
        r.y %= ec.p;
        return r;
    }
    /*static point double_33() {
        if (y == 0) {
            return point{ec};
        }
        bigint temp = 2 * y;
        mpz_invert(temp, temp, ec.p);
        bigint slope{0u};
        slope = ((3 * x * x + ec.a) * temp) % ec.p;
        // slope = ((3 * x * x + ec.a) / (2 * y)) % ec.p;
        point r{ec};
        r.x = (slope * slope - 2 * x) % ec.p;
        r.y = (slope * (x - r.x) - y) % ec.p;
        return r;
    }*/
    point operator+(point q) {
        if (*this == 0) {
            return q;
        }
        if (q == 0) {
            return *this;
        }
        bigint temp1;
        if (q.y != 0) {
            temp1 = (q.y - ec.p);
            temp1 %= ec.p;
        }
        if (y == temp1 && x == q.x) {
            return {ec};
        }
        if (*this == q) {
            return double_();
        }

        bigint temp = (q.x - x);
        temp %= ec.p;
        mpz_invert(temp, temp, ec.p);
        bigint slope{0u};
        slope = ((q.y - y) * temp);
        slope %= ec.p;
        //slope = ((q.y - y) / (q.x - x)) % ec.p;
        point r{ec};
        r.x = (slope * slope - x - q.x);
        r.x %= ec.p;
        r.y = (slope * (x - r.x) - y);
        r.y %= ec.p;
        return r;
    }
};

point operator*(const bigint &m, const point &p) {
    if (m == 0) {
        return {p.ec};
    }
    // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Montgomery_ladder
    point r0{p.ec};
    point r1 = p;
    for (int bit = mpz_sizeinbase(m, 2) - 0; bit >= 0; --bit) {
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
