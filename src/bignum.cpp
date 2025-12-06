#include "bignum.h"
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <sstream>

namespace libzerocoin {

    // Initialize static context
    BN_CTX* CBigNum::ctx = BN_CTX_new();

    CBigNum::CBigNum() {
        bignum = BN_new();
        if (!bignum) {
            throw std::runtime_error("CBigNum::CBigNum(): BN_new failed");
        }
    }

    CBigNum::CBigNum(const CBigNum& b) {
        bignum = BN_new();
        if (!bignum || !BN_copy(bignum, b.bignum)) {
            BN_free(bignum);
            throw std::runtime_error("CBigNum::CBigNum(const CBigNum&): BN_copy failed");
        }
    }

    CBigNum::CBigNum(long long n) {
        bignum = BN_new();
        if (!bignum) {
            throw std::runtime_error("CBigNum::CBigNum(long long): BN_new failed");
        }
        BN_set_word(bignum, std::abs(n));
        if (n < 0) {
            BN_set_negative(bignum, 1);
        }
    }

    CBigNum::~CBigNum() {
        if (bignum) {
            BN_clear_free(bignum);
        }
    }

    CBigNum& CBigNum::operator=(const CBigNum& b) {
        if (this != &b) {
            if (!BN_copy(bignum, b.bignum)) {
                throw std::runtime_error("CBigNum::operator=: BN_copy failed");
            }
        }
        return *this;
    }

    CBigNum CBigNum::operator+(const CBigNum& b) const {
        CBigNum ret;
        if (!BN_add(ret.bignum, bignum, b.bignum)) {
            throw std::runtime_error("CBigNum::operator+: BN_add failed");
        }
        return ret;
    }

    CBigNum CBigNum::operator-(const CBigNum& b) const {
        CBigNum ret;
        if (!BN_sub(ret.bignum, bignum, b.bignum)) {
            throw std::runtime_error("CBigNum::operator-: BN_sub failed");
        }
        return ret;
    }

    CBigNum CBigNum::operator*(const CBigNum& b) const {
        CBigNum ret;
        if (!BN_mul(ret.bignum, bignum, b.bignum, ctx)) {
            throw std::runtime_error("CBigNum::operator*: BN_mul failed");
        }
        return ret;
    }

    CBigNum CBigNum::operator/(const CBigNum& b) const {
        CBigNum ret;
        CBigNum rem;
        if (!BN_div(ret.bignum, rem.bignum, bignum, b.bignum, ctx)) {
            throw std::runtime_error("CBigNum::operator/: BN_div failed");
        }
        return ret;
    }

    CBigNum CBigNum::operator%(const CBigNum& b) const {
        CBigNum ret;
        if (!BN_mod(ret.bignum, bignum, b.bignum, ctx)) {
            throw std::runtime_error("CBigNum::operator%: BN_mod failed");
        }
        return ret;
    }

    // Static methods
    CBigNum CBigNum::generatePrime(const unsigned int numBits, bool safe) {
        CBigNum prime;

        if (safe) {
            if (!BN_generate_prime_ex2(prime.bignum, numBits, 1, nullptr, nullptr, nullptr, ctx)) {
                throw std::runtime_error("CBigNum::generatePrime: BN_generate_prime_ex failed");
            }
        } else {
            if (!BN_generate_prime_ex2(prime.bignum, numBits, 0, nullptr, nullptr, nullptr, ctx)) {
                throw std::runtime_error("CBigNum::generatePrime: BN_generate_prime_ex failed");
            }
        }

        return prime;
    }

    CBigNum CBigNum::randBignum(const CBigNum& range) {
        CBigNum ret;

        if (!BN_rand_range(ret.bignum, range.bignum)) {
            throw std::runtime_error("CBigNum::randBignum: BN_rand_range failed");
        }

        return ret;
    }

    CBigNum CBigNum::randKBitBignum(const uint32_t k) {
        CBigNum ret;

        if (!BN_rand(ret.bignum, k, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
            throw std::runtime_error("CBigNum::randKBitBignum: BN_rand failed");
        }

        return ret;
    }

    // Hash function using OpenSSL 3.5 EVP
    CBigNum CBigNum::sha256() const {
        std::vector<unsigned char> vch = this->getvch();
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLen = 0;

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw std::runtime_error("CBigNum::sha256: EVP_MD_CTX_new failed");
        }

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) <= 0 ||
            EVP_DigestUpdate(ctx, vch.data(), vch.size()) <= 0 ||
            EVP_DigestFinal_ex(ctx, hash, &hashLen) <= 0) {
            EVP_MD_CTX_free(ctx);
        throw std::runtime_error("CBigNum::sha256: Digest operation failed");
            }

            EVP_MD_CTX_free(ctx);

            CBigNum result;
            result.setvch(std::vector<unsigned char>(hash, hash + hashLen));
            return result;
    }

    // Set from vector
    void CBigNum::setvch(const std::vector<unsigned char>& vch) {
        if (vch.empty()) {
            BN_zero(bignum);
            return;
        }

        if (!BN_bin2bn(vch.data(), vch.size(), bignum)) {
            throw std::runtime_error("CBigNum::setvch: BN_bin2bn failed");
        }
    }

    // Get as vector
    std::vector<unsigned char> CBigNum::getvch() const {
        int size = BN_num_bytes(bignum);
        std::vector<unsigned char> vch(size);

        if (!BN_bn2bin(bignum, vch.data())) {
            throw std::runtime_error("CBigNum::getvch: BN_bn2bin failed");
        }

        return vch;
    }

    // To string
    std::string CBigNum::ToString(int nBase) const {
        char* str = BN_bn2dec(bignum);
        if (!str) {
            throw std::runtime_error("CBigNum::ToString: BN_bn2dec failed");
        }
        std::string result(str);
        OPENSSL_free(str);
        return result;
    }

    // Comparison operators
    bool operator==(const CBigNum& a, const CBigNum& b) {
        return BN_cmp(a.bignum, b.bignum) == 0;
    }

    bool operator!=(const CBigNum& a, const CBigNum& b) {
        return BN_cmp(a.bignum, b.bignum) != 0;
    }

    bool operator<=(const CBigNum& a, const CBigNum& b) {
        return BN_cmp(a.bignum, b.bignum) <= 0;
    }

    bool operator>=(const CBigNum& a, const CBigNum& b) {
        return BN_cmp(a.bignum, b.bignum) >= 0;
    }

    bool operator<(const CBigNum& a, const CBigNum& b) {
        return BN_cmp(a.bignum, b.bignum) < 0;
    }

    bool operator>(const CBigNum& a, const CBigNum& b) {
        return BN_cmp(a.bignum, b.bignum) > 0;
    }

} // namespace libzerocoin
