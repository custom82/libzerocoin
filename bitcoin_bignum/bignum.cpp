#include "bignum.h"

#include <openssl/rand.h>
#include <openssl/bn.h>
#include <stdexcept>
#include <cstring>
#include <cctype>

extern "C" {
    // Helper function for hex digit conversion
    int HexDigit(char c) {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    }
}

// Global hex digit table
const char phexdigit[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0,
    0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0
};

void CBigNum::SetHex(const std::string& str) {
    const char* psz = str.c_str();
    bool fNegative = false;

    if (*psz == '-') {
        fNegative = true;
        psz++;
    }

    if (psz[0] == '0' && tolower(static_cast<unsigned char>(psz[1])) == 'x')
        psz += 2;

    while (isspace(static_cast<unsigned char>(*psz)))
        psz++;

    // Start with zero
    if (!BN_set_word(bn, 0))
        throw bignum_error("CBigNum::SetHex : BN_set_word failed");

    while (isxdigit(static_cast<unsigned char>(*psz))) {
        *this <<= 4;
        int n = HexDigit(*psz++);
        if (n < 0)
            break;
        *this += n;
    }

    if (fNegative)
        *this = 0 - *this;
}

void CBigNum::setvch(const std::vector<unsigned char>& vch) {
    BN_bin2bn(vch.data(), vch.size(), bn);
    if (!bn)
        throw bignum_error("CBigNum::setvch : BN_bin2bn failed");
}

std::vector<unsigned char> CBigNum::getvch() const {
    std::vector<unsigned char> vch(BN_num_bytes(bn));
    BN_bn2bin(bn, vch.data());
    return vch;
}

void CBigNum::setuint64(uint64 n) {
    unsigned char pch[sizeof(n) + 6];
    unsigned char* p = pch + 4;
    bool fLeadingZeroes = true;

    for (int i = 0; i < 8; i++) {
        unsigned char c = (n >> 56) & 0xff;
        n <<= 8;
        if (fLeadingZeroes && c == 0)
            continue;
        if (fLeadingZeroes) {
            p[-1] = (i >> 24) & 0xff;
            p[-2] = (i >> 16) & 0xff;
            p[-3] = (i >> 8) & 0xff;
            p[-4] = (i) & 0xff;
            fLeadingZeroes = false;
        }
        *p++ = c;
    }

    unsigned int nSize = p - (pch + 4);
    pch[0] = (nSize >> 24) & 0xff;
    pch[1] = (nSize >> 16) & 0xff;
    pch[2] = (nSize >> 8) & 0xff;
    pch[3] = (nSize) & 0xff;

    BN_mpi2bn(pch, p - pch, bn);
    if (!bn)
        throw bignum_error("CBigNum::setuint64 : BN_mpi2bn failed");
}

void CBigNum::setint64(int64 sn) {
    uint64 n = sn < 0 ? -sn : sn;
    setuint64(n);
    if (sn < 0)
        BN_set_negative(bn, 1);
}

void CBigNum::setuint256(const uint256& n) {
    // Convert uint256 to vector (little-endian)
    std::vector<unsigned char> vch(32);
    memcpy(vch.data(), n.begin(), 32);
    std::reverse(vch.begin(), vch.end()); // Convert to big-endian
    BN_bin2bn(vch.data(), vch.size(), bn);
    if (!bn)
        throw bignum_error("CBigNum::setuint256 : BN_bin2bn failed");
}

std::string CBigNum::ToString(int nBase) const {
    if (nBase == 10) {
        char* psz = BN_bn2dec(bn);
        if (!psz)
            throw bignum_error("CBigNum::ToString : BN_bn2dec failed");
        std::string str(psz);
        OPENSSL_free(psz);
        return str;
    } else if (nBase == 16) {
        char* psz = BN_bn2hex(bn);
        if (!psz)
            throw bignum_error("CBigNum::ToString : BN_bn2hex failed");
        std::string str(psz);
        OPENSSL_free(psz);

        // Remove leading zeros
        while (str.size() > 1 && str[0] == '0' && str[1] == '0')
            str.erase(0, 1);

        return str;
    } else {
        throw bignum_error("CBigNum::ToString : unsupported base");
    }
}

uint256 CBigNum::getuint256() const {
    std::vector<unsigned char> vch = getvch();
    if (vch.size() > 32) {
        throw bignum_error("CBigNum::getuint256 : number too large for uint256");
    }

    // Pad with zeros if necessary
    vch.resize(32, 0);
    std::reverse(vch.begin(), vch.end()); // Convert from big-endian

    uint256 result;
    memcpy(result.begin(), vch.data(), 32);
    return result;
}

CBigNum CBigNum::operator-() const {
    CBigNum ret(*this);
    BN_set_negative(ret.bn, !BN_is_negative(ret.bn));
    return ret;
}

CBigNum& CBigNum::operator+=(const CBigNum& b) {
    if (!BN_add(bn, bn, b.bn))
        throw bignum_error("CBigNum::operator+= : BN_add failed");
    return *this;
}

CBigNum& CBigNum::operator-=(const CBigNum& b) {
    if (!BN_sub(bn, bn, b.bn))
        throw bignum_error("CBigNum::operator-= : BN_sub failed");
    return *this;
}

CBigNum& CBigNum::operator*=(const CBigNum& b) {
    CAutoBN_CTX ctx;
    if (!BN_mul(bn, bn, b.bn, ctx))
        throw bignum_error("CBigNum::operator*= : BN_mul failed");
    return *this;
}

CBigNum& CBigNum::operator/=(const CBigNum& b) {
    CAutoBN_CTX ctx;
    if (!BN_div(bn, nullptr, bn, b.bn, ctx))
        throw bignum_error("CBigNum::operator/= : BN_div failed");
    return *this;
}

CBigNum& CBigNum::operator%=(const CBigNum& b) {
    CAutoBN_CTX ctx;
    if (!BN_mod(bn, bn, b.bn, ctx))
        throw bignum_error("CBigNum::operator%= : BN_mod failed");
    return *this;
}

CBigNum& CBigNum::operator<<=(unsigned int shift) {
    if (!BN_lshift(bn, bn, shift))
        throw bignum_error("CBigNum::operator<<= : BN_lshift failed");
    return *this;
}

CBigNum& CBigNum::operator>>=(unsigned int shift) {
    if (!BN_rshift(bn, bn, shift))
        throw bignum_error("CBigNum::operator>>= : BN_rshift failed");
    return *this;
}

CBigNum CBigNum::pow_mod(const CBigNum& e, const CBigNum& m) const {
    CAutoBN_CTX ctx;
    CBigNum ret;
    if (!BN_mod_exp(ret.bn, bn, e.bn, m.bn, ctx))
        throw bignum_error("CBigNum::pow_mod : BN_mod_exp failed");
    return ret;
}

CBigNum CBigNum::mul_mod(const CBigNum& b, const CBigNum& m) const {
    CAutoBN_CTX ctx;
    CBigNum ret;
    if (!BN_mod_mul(ret.bn, bn, b.bn, m.bn, ctx))
        throw bignum_error("CBigNum::mul_mod : BN_mod_mul failed");
    return ret;
}

CBigNum CBigNum::add_mod(const CBigNum& b, const CBigNum& m) const {
    CAutoBN_CTX ctx;
    CBigNum ret;
    if (!BN_mod_add(ret.bn, bn, b.bn, m.bn, ctx))
        throw bignum_error("CBigNum::add_mod : BN_mod_add failed");
    return ret;
}

CBigNum CBigNum::sub_mod(const CBigNum& b, const CBigNum& m) const {
    CAutoBN_CTX ctx;
    CBigNum ret;
    if (!BN_mod_sub(ret.bn, bn, b.bn, m.bn, ctx))
        throw bignum_error("CBigNum::sub_mod : BN_mod_sub failed");
    return ret;
}

CBigNum CBigNum::inverse(const CBigNum& m) const {
    CAutoBN_CTX ctx;
    CBigNum ret;
    if (!BN_mod_inverse(ret.bn, bn, m.bn, ctx))
        throw bignum_error("CBigNum::inverse : BN_mod_inverse failed");
    return ret;
}

CBigNum CBigNum::generatePrime(uint32_t bits, bool safe) {
    CBigNum ret;
    BN_GENCB* cb = BN_GENCB_new();
    if (!cb) {
        throw bignum_error("CBigNum::generatePrime : BN_GENCB_new failed");
    }

    int retcode = BN_generate_prime_ex2(ret.bn, bits, safe ? 1 : 0, nullptr, nullptr, cb, nullptr);
    BN_GENCB_free(cb);

    if (retcode != 1) {
        throw bignum_error("CBigNum::generatePrime : BN_generate_prime_ex2 failed");
    }
    return ret;
}

bool CBigNum::isPrime(int checks, BN_GENCB* cb) const {
    return BN_is_prime_ex(bn, checks, nullptr, cb) == 1;
}

CBigNum CBigNum::gcd(const CBigNum& b) const {
    CAutoBN_CTX ctx;
    CBigNum ret;
    if (!BN_gcd(ret.bn, bn, b.bn, ctx))
        throw bignum_error("CBigNum::gcd : BN_gcd failed");
    return ret;
}

CBigNum CBigNum::sqrt_mod(const CBigNum& p) const {
    CAutoBN_CTX ctx;
    CBigNum ret;

    // Check if p is prime
    if (!BN_is_prime_ex(p.bn, 20, nullptr, nullptr)) {
        throw bignum_error("CBigNum::sqrt_mod : p is not prime");
    }

    if (!BN_mod_sqrt(ret.bn, bn, p.bn, ctx)) {
        throw bignum_error("CBigNum::sqrt_mod : BN_mod_sqrt failed");
    }
    return ret;
}
