#pragma once

#include "bigint.h"

#include <gmpxx.h>

// what about timing attacks & gmp?

namespace crypto {

struct bigint : mpz_class {
    using mpz_class::mpz_class;
    using mpz_class::operator=;

    bigint(const char *c) : mpz_class{c} {}

    operator mpz_ptr() { return __get_mp(); }
    operator mpz_srcptr() const { return __get_mp(); }
};

template <auto N>
bigint bytes_to_bigint(uint8_t (&v)[N], int order = 1) {
    bigint b;
    mpz_import(b.__get_mp(), N, order, sizeof(v[0]), 0, 0, v);
    return b;
}

}
