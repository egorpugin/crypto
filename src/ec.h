#pragma once

#include "bigint.h"

namespace crypto::ec {

struct simple {
    bigint a,b,p;
};

struct point {
    simple &ec;
    bigint x,y;

    point operator+(const point &rhs) {
        point r{ec};
        return r;
    }
    auto double_() {
        point r{ec};
        mpz_t slope, temp;
        mpz_init(temp);
        mpz_init(slope);

        if (mpz_cmp_ui(y, 0) != 0) {
            mpz_mul_ui(temp, y, 2);
            mpz_invert(temp, temp, ec.p);
            mpz_mul(slope, x, x);
            mpz_mul_ui(slope, slope, 3);
            mpz_add(slope, slope, ec.a);
            mpz_mul(slope, slope, temp);
            mpz_mod(slope, slope, ec.p);
            mpz_mul(r.x, slope, slope);
            mpz_sub(r.x, r.x, x);
            mpz_sub(r.x, r.x, x);
            mpz_mod(r.x, r.x, ec.p);
            mpz_sub(temp, x, r.x);
            mpz_mul(r.y, slope, temp);
            mpz_sub(r.y, r.y, y);
            mpz_mod(r.y, r.y, ec.p);
        } else {
            mpz_set_ui(r.x, 0);
            mpz_set_ui(r.y, 0);
        }
        mpz_clear(temp);
        mpz_clear(slope);
        return r;
    }

    void Point_Doubling(point P, point *R) {
        auto &EC = ec;

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
    }
    void Point_Addition(point P, point Q, point *R) {
        auto &EC = ec;

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
            return;
        }

        if (mpz_cmp(P.x, Q.x) == 0 && mpz_cmp(P.y, Q.y) == 0) {
            Point_Doubling(P, R);
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
        }
    }

    void Scalar_Multiplication(point P, point *R, mpz_t m) {
        point Q{ec}, T{ec};
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
    }

};
point operator*(const bigint &k, const point &p) {
    return p;
}

} // namespace crypto::ec
