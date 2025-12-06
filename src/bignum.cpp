#include "bignum.h"
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdexcept>

namespace libzerocoin {

    // Static initialization for context
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

    CBigNum::~CBigNum() {
        if (bignum) {
            BN_clear_free(bignum);
        }
    }

    CBigNum& CBigNum::operator=(const CBigNum& b) {
        if (!BN_copy(bignum, b.bignum)) {
            throw std::runtime_error("CBigNum::operator=: BN_copy failed");
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
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_mul(ret.bignum, bignum, b.bignum, pctx)) {
            throw std::runtime_error("CBigNum::operator*: BN_mul failed");
        }
        return ret;
    }

    CBigNum CBigNum::operator/(const CBigNum& b) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_div(ret.bignum, nullptr, bignum, b.bignum, pctx)) {
            throw std::runtime_error("CBigNum::operator/: BN_div failed");
        }
        return ret;
    }

    CBigNum CBigNum::operator%(const CBigNum& b) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_mod(ret.bignum, bignum, b.bignum, pctx)) {
            throw std::runtime_error("CBigNum::operator%: BN_mod failed");
        }
        return ret;
    }

    // Genera un numero primo usando OpenSSL 3.5 EVP API
    CBigNum CBigNum::generatePrime(const unsigned int numBits, bool safe) {
        CBigNum prime;

        // Usa EVP_PKEY per generazione RSA (che genera numeri primi)
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) {
            throw std::runtime_error("CBigNum::generatePrime: EVP_PKEY_CTX_new_id failed");
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("CBigNum::generatePrime: EVP_PKEY_keygen_init failed");
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, numBits) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("CBigNum::generatePrime: EVP_PKEY_CTX_set_rsa_keygen_bits failed");
        }

        EVP_PKEY *pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("CBigNum::generatePrime: EVP_PKEY_keygen failed");
        }

        // Estrai il modulo N (che contiene il numero primo per RSA)
        BIGNUM *n = nullptr;
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) <= 0) {
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("CBigNum::generatePrime: EVP_PKEY_get_bn_param failed");
        }

        if (!BN_copy(prime.bignum, n)) {
            BN_free(n);
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("CBigNum::generatePrime: BN_copy failed");
        }

        BN_free(n);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);

        return prime;
    }

    // Random number generation using OpenSSL 3.5
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

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
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
        std::vector<unsigned char> vch(BN_num_bytes(bignum));

        if (!BN_bn2bin(bignum, vch.data())) {
            throw std::runtime_error("CBigNum::getvch: BN_bn2bin failed");
        }

        return vch;
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
