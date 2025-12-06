#include "bignum.h"
#include "bignum_error.h"
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iomanip>

// Costruttore default
CBigNum::CBigNum() : bn(BN_new()) {
    BN_zero(bn);
}

// Costruttore di copia
CBigNum::CBigNum(const CBigNum& b) : bn(BN_new()) {
    if (!BN_copy(bn, b.bn)) {
        BN_free(bn);
        throw bignum_error("CBigNum::CBigNum(const CBigNum&) : BN_copy failed");
    }
}

// Costruttori da tipi interi
#define IMPL_INT_CONSTRUCTOR(type, bn_func) \
CBigNum::CBigNum(type n) : bn(BN_new()) { \
    if (n >= 0) { \
        if (!bn_func(bn, n)) { \
            BN_free(bn); \
            throw bignum_error("CBigNum::CBigNum(" #type ") failed"); \
        } \
    } else { \
        if (!bn_func(bn, -n)) { \
            BN_free(bn); \
            throw bignum_error("CBigNum::CBigNum(" #type ") failed"); \
        } \
        BN_set_negative(bn, 1); \
    } \
}

IMPL_INT_CONSTRUCTOR(signed char, BN_set_word)
IMPL_INT_CONSTRUCTOR(short, BN_set_word)
IMPL_INT_CONSTRUCTOR(int, BN_set_word)
IMPL_INT_CONSTRUCTOR(long, BN_set_word)
CBigNum::CBigNum(long long n) : bn(BN_new()) {
    if (n >= 0) {
        BN_set_word(bn, n);
    } else {
        BN_set_word(bn, -n);
        BN_set_negative(bn, 1);
    }
}

IMPL_INT_CONSTRUCTOR(unsigned char, BN_set_word)
IMPL_INT_CONSTRUCTOR(unsigned short, BN_set_word)
IMPL_INT_CONSTRUCTOR(unsigned int, BN_set_word)
IMPL_INT_CONSTRUCTOR(unsigned long, BN_set_word)
CBigNum::CBigNum(unsigned long long n) : bn(BN_new()) {
    // Per numeri > 64-bit, usa approssimazione
    BN_set_word(bn, (unsigned long)(n & 0xFFFFFFFF));
    if (n > 0xFFFFFFFF) {
        BIGNUM* temp = BN_new();
        BN_set_word(temp, (unsigned long)(n >> 32));
        BN_lshift(temp, temp, 32);
        BN_add(bn, bn, temp);
        BN_free(temp);
    }
}

#undef IMPL_INT_CONSTRUCTOR

// Costruttore da vettore
CBigNum::CBigNum(const std::vector<unsigned char>& vch) : bn(BN_new()) {
    BN_bin2bn(vch.data(), vch.size(), bn);
}

// Distruttore
CBigNum::~CBigNum() {
    if (bn) BN_free(bn);
}

// Operatore di assegnazione
CBigNum& CBigNum::operator=(const CBigNum& b) {
    if (this != &b) {
        if (!BN_copy(bn, b.bn)) {
            throw bignum_error("CBigNum::operator= : BN_copy failed");
        }
    }
    return *this;
}

// Operatori aritmetici
CBigNum CBigNum::operator+(const CBigNum& b) const {
    CBigNum r;
    if (!BN_add(r.bn, bn, b.bn))
        throw bignum_error("CBigNum::operator+ : BN_add failed");
    return r;
}

CBigNum CBigNum::operator-(const CBigNum& b) const {
    CBigNum r;
    if (!BN_sub(r.bn, bn, b.bn))
        throw bignum_error("CBigNum::operator- : BN_sub failed");
    return r;
}

CBigNum CBigNum::operator*(const CBigNum& b) const {
    CBigNum r;
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw bignum_error("CBigNum::operator* : BN_CTX_new failed");

    if (!BN_mul(r.bn, bn, b.bn, ctx))
        throw bignum_error("CBigNum::operator* : BN_mul failed");

    BN_CTX_free(ctx);
    return r;
}

CBigNum CBigNum::operator/(const CBigNum& b) const {
    CBigNum r;
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw bignum_error("CBigNum::operator/ : BN_CTX_new failed");

    if (!BN_div(r.bn, NULL, bn, b.bn, ctx))
        throw bignum_error("CBigNum::operator/ : BN_div failed");

    BN_CTX_free(ctx);
    return r;
}

CBigNum CBigNum::operator%(const CBigNum& b) const {
    CBigNum r;
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw bignum_error("CBigNum::operator% : BN_CTX_new failed");

    if (!BN_mod(r.bn, bn, b.bn, ctx))
        throw bignum_error("CBigNum::operator% : BN_mod failed");

    BN_CTX_free(ctx);
    return r;
}

CBigNum CBigNum::operator-() const {
    CBigNum r(*this);
    BN_set_negative(r.bn, !BN_is_negative(r.bn));
    return r;
}

// Operatori composti (implementazioni simili - ecco uno come esempio)
CBigNum& CBigNum::operator+=(const CBigNum& b) {
    if (!BN_add(bn, bn, b.bn))
        throw bignum_error("CBigNum::operator+= : BN_add failed");
    return *this;
}

// Operatori di confronto
bool CBigNum::operator==(const CBigNum& b) const {
    return BN_cmp(bn, b.bn) == 0;
}

bool CBigNum::operator!=(const CBigNum& b) const {
    return BN_cmp(bn, b.bn) != 0;
}

bool CBigNum::operator<=(const CBigNum& b) const {
    return BN_cmp(bn, b.bn) <= 0;
}

bool CBigNum::operator>=(const CBigNum& b) const {
    return BN_cmp(bn, b.bn) >= 0;
}

bool CBigNum::operator<(const CBigNum& b) const {
    return BN_cmp(bn, b.bn) < 0;
}

bool CBigNum::operator>(const CBigNum& b) const {
    return BN_cmp(bn, b.bn) > 0;
}

// Metodi di conversione
void CBigNum::setuint64(uint64_t n) {
    BN_set_word(bn, (unsigned long)(n & 0xFFFFFFFF));
    if (n > 0xFFFFFFFF) {
        BIGNUM* temp = BN_new();
        BN_set_word(temp, (unsigned long)(n >> 32));
        BN_lshift(temp, temp, 32);
        BN_add(bn, bn, temp);
        BN_free(temp);
    }
}

void CBigNum::setint64(int64_t n) {
    if (n >= 0) {
        setuint64(n);
    } else {
        setuint64(-n);
        BN_set_negative(bn, 1);
    }
}

void CBigNum::setvch(const std::vector<unsigned char>& vch) {
    BN_bin2bn(vch.data(), vch.size(), bn);
}

std::vector<unsigned char> CBigNum::getvch() const {
    std::vector<unsigned char> vch(BN_num_bytes(bn));
    BN_bn2bin(bn, vch.data());
    return vch;
}

void CBigNum::SetHex(const std::string& str) {
    if (BN_hex2bn(&bn, str.c_str()) == 0)
        throw bignum_error("CBigNum::SetHex : BN_hex2bn failed");
}

std::string CBigNum::GetHex() const {
    char* hex = BN_bn2hex(bn);
    if (!hex) throw bignum_error("CBigNum::GetHex : BN_bn2hex failed");

    std::string str(hex);
    OPENSSL_free(hex);
    return str;
}

std::string CBigNum::ToString(int nBase) const {
    if (nBase == 10) {
        char* dec = BN_bn2dec(bn);
        if (!dec) throw bignum_error("CBigNum::ToString : BN_bn2dec failed");

        std::string str(dec);
        OPENSSL_free(dec);
        return str;
    } else if (nBase == 16) {
        return GetHex();
    } else {
        throw bignum_error("CBigNum::ToString : unsupported base");
    }
}

// Funzioni crittografiche
CBigNum CBigNum::randBignum(const CBigNum& range) {
    CBigNum result;
    if (range.bn && BN_num_bits(range.bn) > 0) {
        BN_rand_range(result.bn, range.bn);
    }
    return result;
}

CBigNum CBigNum::generatePrime(unsigned int bits, bool safe) {
    CBigNum r;
    if (!BN_generate_prime_ex(r.bn, bits, safe ? 1 : 0, NULL, NULL, NULL))
        throw bignum_error("CBigNum::generatePrime : BN_generate_prime_ex failed");
    return r;
}

CBigNum CBigNum::pow_mod(const CBigNum& e, const CBigNum& m) const {
    CBigNum r;
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw bignum_error("CBigNum::pow_mod : BN_CTX_new failed");

    if (!BN_mod_exp(r.bn, bn, e.bn, m.bn, ctx))
        throw bignum_error("CBigNum::pow_mod : BN_mod_exp failed");

    BN_CTX_free(ctx);
    return r;
}

CBigNum CBigNum::inverse(const CBigNum& m) const {
    CBigNum r;
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw bignum_error("CBigNum::inverse : BN_CTX_new failed");

    if (!BN_mod_inverse(r.bn, bn, m.bn, ctx))
        throw bignum_error("CBigNum::inverse : BN_mod_inverse failed");

    BN_CTX_free(ctx);
    return r;
}

bool CBigNum::isPrime(int checks) const {
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw bignum_error("CBigNum::isPrime : BN_CTX_new failed");

    int ret = BN_is_prime_ex(bn, checks, ctx, NULL);
    BN_CTX_free(ctx);

    return ret == 1;
}

// Implementa altri metodi simili...
