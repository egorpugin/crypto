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

    point &operator=(const point &rhs) {
        x = rhs.x;
        y = rhs.y;
        return *this;
    }
    point operator+(const point &rhs) {
        point r{ec};
        return r;
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
    point Point_Addition(point P, point Q) const {
        P.x %= ec.p;
        P.y %= ec.p;
        Q.x %= ec.p;
        Q.y %= ec.p;

        if (P.x == 0 && P.y == 0) {
            return Q;
        }
        if (Q.x == 0 && Q.y == 0) {
            return P;
        }
        if (Q.y != 0 && P.y == -Q.y && P.x == Q.x) {
            return {ec};
        }
        if (P.x == Q.x && P.y == Q.y) {
            return P.double_();
        }

        bigint slope;
        bigint temp;
        mpz_sub(temp, P.x, Q.x);
        mpz_mod(temp, temp, ec.p);
        mpz_invert(temp, temp, ec.p);
        mpz_sub(slope, P.y, Q.y);
        mpz_mul(slope, slope, temp);
        mpz_mod(slope, slope, ec.p);
        point r{ec};
        r.x = slope * slope;
        mpz_sub(r.x, r.x, P.x);
        mpz_sub(r.x, r.x, Q.x);
        mpz_mod(r.x, r.x, ec.p);
        mpz_sub(temp, P.x, r.x);
        mpz_mul(r.y, slope, temp);
        mpz_sub(r.y, r.y, P.y);
        mpz_mod(r.y, r.y, ec.p);
        return r;
    }
};
// can be time attacked!
point operator*(const bigint &m, const point &p) {
    point r{p.ec};
    long no_of_bits;

    no_of_bits = mpz_sizeinbase(m, 2);
    if (m == 0) {
        return r;
    }
    if (mpz_tstbit(m, 0) == 1) {
        r = p;
    }
    auto q = p;
    for (int loop = 1; loop < no_of_bits; loop++) {
        auto t = q.double_();
        q = t;
        t = r;
        if (mpz_tstbit(m, loop)) {
            r = p.Point_Addition(t, q);
        } else {
            // time attack is here!
            // in empty branch
        }
    }
    return r;
}

} // namespace crypto::ec
