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


struct Point {
    mpz_t x;
    mpz_t y;
};
simple EC;

void Point_Doubling(Point P, Point *R) {
    mpz_t slope, temp;
    mpz_init(temp);
    mpz_init(slope);

    if (mpz_cmp_ui(P.y, 0) != 0) {
        mpz_mul_ui(temp, P.y, 2);
        mpz_invert(temp, temp, EC.p);
        mpz_mul(slope, P.x, P.x);
        mpz_mul_ui(slope, slope, 3);
        mpz_add(slope, slope, EC.a);
        mpz_mul(slope, slope, temp);
        mpz_mod(slope, slope, EC.p);
        mpz_mul(R->x, slope, slope);
        mpz_sub(R->x, R->x, P.x);
        mpz_sub(R->x, R->x, P.x);
        mpz_mod(R->x, R->x, EC.p);
        mpz_sub(temp, P.x, R->x);
        mpz_mul(R->y, slope, temp);
        mpz_sub(R->y, R->y, P.y);
        mpz_mod(R->y, R->y, EC.p);
    } else {
        mpz_set_ui(R->x, 0);
        mpz_set_ui(R->y, 0);
    }
    mpz_clear(temp);
    mpz_clear(slope);
}

void Point_Addition(Point P, Point Q, Point *R) {
    mpz_mod(P.x, P.x, EC.p);
    mpz_mod(P.y, P.y, EC.p);
    mpz_mod(Q.x, Q.x, EC.p);
    mpz_mod(Q.y, Q.y, EC.p);

    if (mpz_cmp_ui(P.x, 0) == 0 && mpz_cmp_ui(P.y, 0) == 0) {
        mpz_set(R->x, Q.x);
        mpz_set(R->y, Q.y);
        return;
    }

    if (mpz_cmp_ui(Q.x, 0) == 0 && mpz_cmp_ui(Q.y, 0) == 0) {
        mpz_set(R->x, P.x);
        mpz_set(R->y, P.y);
        return;
    }

    mpz_t temp;
    mpz_init(temp);

    if (mpz_cmp_ui(Q.y, 0) != 0) {
        mpz_sub(temp, EC.p, Q.y);
        mpz_mod(temp, temp, EC.p);
    } else
        mpz_set_ui(temp, 0);

    // gmp_printf("\n temp=%Zd\n", temp);

    if (mpz_cmp(P.y, temp) == 0 && mpz_cmp(P.x, Q.x) == 0) {
        mpz_set_ui(R->x, 0);
        mpz_set_ui(R->y, 0);
        mpz_clear(temp);
        return;
    }

    if (mpz_cmp(P.x, Q.x) == 0 && mpz_cmp(P.y, Q.y) == 0) {
        Point_Doubling(P, R);

        mpz_clear(temp);
        return;
    } else {
        mpz_t slope;
        mpz_init_set_ui(slope, 0);

        mpz_sub(temp, P.x, Q.x);
        mpz_mod(temp, temp, EC.p);
        mpz_invert(temp, temp, EC.p);
        mpz_sub(slope, P.y, Q.y);
        mpz_mul(slope, slope, temp);
        mpz_mod(slope, slope, EC.p);
        mpz_mul(R->x, slope, slope);
        mpz_sub(R->x, R->x, P.x);
        mpz_sub(R->x, R->x, Q.x);
        mpz_mod(R->x, R->x, EC.p);
        mpz_sub(temp, P.x, R->x);
        mpz_mul(R->y, slope, temp);
        mpz_sub(R->y, R->y, P.y);
        mpz_mod(R->y, R->y, EC.p);

        mpz_clear(temp);
        mpz_clear(slope);
        return;
    }
}

void Scalar_Multiplication(Point P, Point *R, mpz_t m) {
    Point Q, T;
    mpz_init(Q.x);
    mpz_init(Q.y);
    mpz_init(T.x);
    mpz_init(T.y);
    long no_of_bits, loop;

    no_of_bits = mpz_sizeinbase(m, 2);
    mpz_set_ui(R->x, 0);
    mpz_set_ui(R->y, 0);
    if (mpz_cmp_ui(m, 0) == 0)
        return;

    mpz_set(Q.x, P.x);
    mpz_set(Q.y, P.y);
    if (mpz_tstbit(m, 0) == 1) {
        mpz_set(R->x, P.x);
        mpz_set(R->y, P.y);
    }

    for (loop = 1; loop < no_of_bits; loop++) {
        mpz_set_ui(T.x, 0);
        mpz_set_ui(T.y, 0);
        Point_Doubling(Q, &T);

        // gmp_printf("\n %Zd %Zd %Zd %Zd ", Q.x, Q.y, T.x, T.y);
        mpz_set(Q.x, T.x);
        mpz_set(Q.y, T.y);
        mpz_set(T.x, R->x);
        mpz_set(T.y, R->y);
        if (mpz_tstbit(m, loop))
            Point_Addition(T, Q, R);
    }

    mpz_clear(Q.x);
    mpz_clear(Q.y);
    mpz_clear(T.x);
    mpz_clear(T.y);
}

} // namespace crypto::ec

