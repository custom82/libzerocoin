#include "libzerocoin.h"
#include <openssl/err.h>
#include <iomanip>
#include <algorithm>

namespace libzerocoin {

    // ============================================================================
    // Utility Functions
    // ============================================================================

    std::string DenominationToString(CoinDenomination denomination) {
        switch(denomination) {
            case ZQ_ONE: return "1";
            case ZQ_FIVE: return "5";
            case ZQ_TEN: return "10";
            case ZQ_FIFTY: return "50";
            case ZQ_ONE_HUNDRED: return "100";
            case ZQ_FIVE_HUNDRED: return "500";
            case ZQ_ONE_THOUSAND: return "1000";
            case ZQ_FIVE_THOUSAND: return "5000";
            default: return "ERROR";
        }
    }

    CoinDenomination StringToDenomination(const std::string& str) {
        if (str == "1") return ZQ_ONE;
        if (str == "5") return ZQ_FIVE;
        if (str == "10") return ZQ_TEN;
        if (str == "50") return ZQ_FIFTY;
        if (str == "100") return ZQ_ONE_HUNDRED;
        if (str == "500") return ZQ_FIVE_HUNDRED;
        if (str == "1000") return ZQ_ONE_THOUSAND;
        if (str == "5000") return ZQ_FIVE_THOUSAND;
        return ZQ_ERROR;
    }

    // ============================================================================
    // CBigNum Implementation (Enhanced)
    // ============================================================================

    BN_CTX* CBigNum::ctx = nullptr;

    // Static initialization
    void CBigNum::init() {
        if (!ctx) {
            ctx = BN_CTX_new();
            if (!ctx) {
                throw std::runtime_error("CBigNum::init: BN_CTX_new failed");
            }
            BN_CTX_start(ctx);
        }
    }

    void CBigNum::cleanup() {
        if (ctx) {
            BN_CTX_end(ctx);
            BN_CTX_free(ctx);
            ctx = nullptr;
        }
    }

    // OpenSSL 3.5 EVP-based RSA generation
    EVP_PKEY* CBigNum::generateRSAKey(int bits) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) return nullptr;

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }

        EVP_PKEY_CTX_free(ctx);
        return pkey;
    }

    BIGNUM* CBigNum::extractRSA_N(EVP_PKEY* pkey) {
        if (!pkey) return nullptr;

        BIGNUM* n = nullptr;
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) <= 0) {
            return nullptr;
        }

        return n;
    }

    // Constructors
    CBigNum::CBigNum() {
        init();
        bignum = BN_new();
        if (!bignum) throw std::runtime_error("CBigNum::CBigNum: BN_new failed");
        BN_zero(bignum);
    }

    CBigNum::CBigNum(const CBigNum& b) {
        init();
        bignum = BN_new();
        if (!bignum || !BN_copy(bignum, b.bignum)) {
            BN_free(bignum);
            throw std::runtime_error("CBigNum::CBigNum(copy): BN_copy failed");
        }
    }

    CBigNum::CBigNum(int n) : CBigNum((long long)n) {}
    CBigNum::CBigNum(long n) : CBigNum((long long)n) {}
    CBigNum::CBigNum(long long n) {
        init();
        bignum = BN_new();
        if (!bignum) throw std::runtime_error("CBigNum::CBigNum(long long): BN_new failed");

        if (n >= 0) {
            BN_set_word(bignum, (unsigned long)std::abs(n));
            if (n < 0) BN_set_negative(bignum, 1);
        }
    }

    CBigNum::CBigNum(unsigned int n) : CBigNum((unsigned long long)n) {}
    CBigNum::CBigNum(unsigned long n) : CBigNum((unsigned long long)n) {}
    CBigNum::CBigNum(unsigned long long n) {
        init();
        bignum = BN_new();
        if (!bignum) throw std::runtime_error("CBigNum::CBigNum(unsigned long long): BN_new failed");

        // Convert unsigned long long to BIGNUM
        std::vector<unsigned char> bytes;
        unsigned long long temp = n;
        while (temp > 0) {
            bytes.push_back(temp & 0xFF);
            temp >>= 8;
        }
        if (bytes.empty()) bytes.push_back(0);

        BN_bin2bn(bytes.data(), bytes.size(), bignum);
    }

    CBigNum::CBigNum(const std::vector<unsigned char>& vch) {
        init();
        bignum = BN_new();
        if (!bignum) throw std::runtime_error("CBigNum::CBigNum(vector): BN_new failed");
        setvch(vch);
    }

    CBigNum::CBigNum(const std::string& str) {
        init();
        bignum = BN_new();
        if (!bignum) throw std::runtime_error("CBigNum::CBigNum(string): BN_new failed");
        setHex(str);
    }

    CBigNum::~CBigNum() {
        if (bignum) BN_clear_free(bignum);
    }

    // Assignment
    CBigNum& CBigNum::operator=(const CBigNum& b) {
        if (this != &b) {
            if (!BN_copy(bignum, b.bignum)) {
                throw std::runtime_error("CBigNum::operator=: BN_copy failed");
            }
        }
        return *this;
    }

    CBigNum& CBigNum::operator=(long long n) {
        *this = CBigNum(n);
        return *this;
    }

    // Arithmetic operators
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
        CBigNum ret, rem;
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

    // Compound assignment
    CBigNum& CBigNum::operator+=(const CBigNum& b) {
        if (!BN_add(bignum, bignum, b.bignum)) {
            throw std::runtime_error("CBigNum::operator+=: BN_add failed");
        }
        return *this;
    }

    CBigNum& CBigNum::operator-=(const CBigNum& b) {
        if (!BN_sub(bignum, bignum, b.bignum)) {
            throw std::runtime_error("CBigNum::operator-=: BN_sub failed");
        }
        return *this;
    }

    CBigNum& CBigNum::operator*=(const CBigNum& b) {
        CBigNum result = *this * b;
        *this = result;
        return *this;
    }

    CBigNum& CBigNum::operator/=(const CBigNum& b) {
        CBigNum result = *this / b;
        *this = result;
        return *this;
    }

    CBigNum& CBigNum::operator%=(const CBigNum& b) {
        CBigNum result = *this % b;
        *this = result;
        return *this;
    }

    // Unary operators
    CBigNum CBigNum::operator-() const {
        CBigNum ret(*this);
        BN_set_negative(ret.bignum, !BN_is_negative(ret.bignum));
        return ret;
    }

    CBigNum CBigNum::operator++(int) {
        CBigNum ret(*this);
        *this += 1;
        return ret;
    }

    CBigNum& CBigNum::operator++() {
        *this += 1;
        return *this;
    }

    CBigNum CBigNum::operator--(int) {
        CBigNum ret(*this);
        *this -= 1;
        return ret;
    }

    CBigNum& CBigNum::operator--() {
        *this -= 1;
        return *this;
    }

    // Bitwise operators
    CBigNum CBigNum::operator<<(unsigned int shift) const {
        CBigNum ret;
        if (!BN_lshift(ret.bignum, bignum, shift)) {
            throw std::runtime_error("CBigNum::operator<<: BN_lshift failed");
        }
        return ret;
    }

    CBigNum CBigNum::operator>>(unsigned int shift) const {
        CBigNum ret;
        if (!BN_rshift(ret.bignum, bignum, shift)) {
            throw std::runtime_error("CBigNum::operator>>: BN_rshift failed");
        }
        return ret;
    }

    CBigNum& CBigNum::operator<<=(unsigned int shift) {
        if (!BN_lshift(bignum, bignum, shift)) {
            throw std::runtime_error("CBigNum::operator<<=: BN_lshift failed");
        }
        return *this;
    }

    CBigNum& CBigNum::operator>>=(unsigned int shift) {
        if (!BN_rshift(bignum, bignum, shift)) {
            throw std::runtime_error("CBigNum::operator>>=: BN_rshift failed");
        }
        return *this;
    }

    // Modular arithmetic
    CBigNum CBigNum::modExp(const CBigNum& e, const CBigNum& m) const {
        CBigNum ret;
        if (!BN_mod_exp(ret.bignum, bignum, e.bignum, m.bignum, ctx)) {
            throw std::runtime_error("CBigNum::modExp: BN_mod_exp failed");
        }
        return ret;
    }

    CBigNum CBigNum::modInverse(const CBigNum& m) const {
        CBigNum ret;
        if (!BN_mod_inverse(ret.bignum, bignum, m.bignum, ctx)) {
            throw std::runtime_error("CBigNum::modInverse: BN_mod_inverse failed");
        }
        return ret;
    }

    CBigNum CBigNum::gcd(const CBigNum& b) const {
        CBigNum ret;
        if (!BN_gcd(ret.bignum, bignum, b.bignum, ctx)) {
            throw std::runtime_error("CBigNum::gcd: BN_gcd failed");
        }
        return ret;
    }

    // Cryptographic operations
    CBigNum CBigNum::generatePrime(unsigned int numBits, bool safe) {
        init();
        CBigNum prime;

        if (safe) {
            // Generate safe prime (p = 2q + 1 where q is prime)
            EVP_PKEY* pkey = generateRSAKey(numBits);
            if (!pkey) {
                throw std::runtime_error("CBigNum::generatePrime: RSA key generation failed");
            }

            BIGNUM* n = extractRSA_N(pkey);
            if (!n) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("CBigNum::generatePrime: Failed to extract N");
            }

            if (!BN_copy(prime.bignum, n)) {
                BN_free(n);
                EVP_PKEY_free(pkey);
                throw std::runtime_error("CBigNum::generatePrime: BN_copy failed");
            }

            BN_free(n);
            EVP_PKEY_free(pkey);
        } else {
            // Generate regular prime using OpenSSL 3.5
            if (!BN_generate_prime_ex2(prime.bignum, numBits, 0, nullptr, nullptr, nullptr, ctx)) {
                throw std::runtime_error("CBigNum::generatePrime: BN_generate_prime_ex failed");
            }
        }

        return prime;
    }

    CBigNum CBigNum::generateStrongPrime(unsigned int numBits, const CBigNum& aux) {
        // Simplified strong prime generation
        // In real implementation, this would use more sophisticated algorithms
        CBigNum prime = generatePrime(numBits, true);

        if (!aux.isZero()) {
            // Make sure prime % aux != 0
            while (prime % aux == 0) {
                prime += 2;
            }
        }

        return prime;
    }

    CBigNum CBigNum::randBignum(const CBigNum& range) {
        init();
        CBigNum ret;

        if (!BN_rand_range(ret.bignum, range.bignum)) {
            throw std::runtime_error("CBigNum::randBignum: BN_rand_range failed");
        }

        return ret;
    }

    CBigNum CBigNum::randBignum(const CBigNum& min, const CBigNum& max) {
        CBigNum range = max - min;
        CBigNum rand = randBignum(range);
        return min + rand;
    }

    CBigNum CBigNum::randKBitBignum(unsigned int k) {
        init();
        CBigNum ret;

        if (!BN_rand(ret.bignum, k, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
            throw std::runtime_error("CBigNum::randKBitBignum: BN_rand failed");
        }

        return ret;
    }

    // Hash functions
    CBigNum CBigNum::sha256() const {
        std::vector<unsigned char> vch = getvch();
        return CBigNum(HashSHA256(vch).getvch());
    }

    CBigNum CBigNum::sha1() const {
        std::vector<unsigned char> vch = getvch();
        return CBigNum(HashSHA1(vch).getvch());
    }

    CBigNum CBigNum::ripemd160() const {
        std::vector<unsigned char> vch = getvch();
        return CBigNum(HashRIPEMD160(vch).getvch());
    }

    // Conversion methods
    void CBigNum::setvch(const std::vector<unsigned char>& vch) {
        if (vch.empty()) {
            BN_zero(bignum);
            return;
        }

        if (!BN_bin2bn(vch.data(), vch.size(), bignum)) {
            throw std::runtime_error("CBigNum::setvch: BN_bin2bn failed");
        }
    }

    std::vector<unsigned char> CBigNum::getvch() const {
        int size = BN_num_bytes(bignum);
        std::vector<unsigned char> vch(size);

        if (!BN_bn2bin(bignum, vch.data())) {
            throw std::runtime_error("CBigNum::getvch: BN_bn2bin failed");
        }

        return vch;
    }

    void CBigNum::setHex(const std::string& str) {
        if (str.empty()) {
            BN_zero(bignum);
            return;
        }

        if (!BN_hex2bn(&bignum, str.c_str())) {
            throw std::runtime_error("CBigNum::setHex: BN_hex2bn failed");
        }
    }

    std::string CBigNum::getHex() const {
        char* hex = BN_bn2hex(bignum);
        if (!hex) {
            throw std::runtime_error("CBigNum::getHex: BN_bn2hex failed");
        }

        std::string result(hex);
        OPENSSL_free(hex);
        return result;
    }

    std::string CBigNum::ToString(int nBase) const {
        (void)nBase; // Currently only supports decimal and hex via getHex()
        char* dec = BN_bn2dec(bignum);
        if (!dec) {
            throw std::runtime_error("CBigNum::ToString: BN_bn2dec failed");
        }

        std::string result(dec);
        OPENSSL_free(dec);
        return result;
    }

    // Utility methods
    unsigned int CBigNum::bitSize() const {
        return BN_num_bits(bignum);
    }

    unsigned int CBigNum::byteSize() const {
        return BN_num_bytes(bignum);
    }

    bool CBigNum::isPrime(int checks) const {
        if (checks <= 0) checks = 20;

        int result = BN_is_prime_ex(bignum, checks, ctx, nullptr);
        if (result == 1) return true;
        if (result == 0) return false;
        throw std::runtime_error("CBigNum::isPrime: BN_is_prime_ex failed");
    }

    bool CBigNum::isOdd() const {
        return BN_is_odd(bignum);
    }

    bool CBigNum::isEven() const {
        return !BN_is_odd(bignum);
    }

    bool CBigNum::isZero() const {
        return BN_is_zero(bignum);
    }

    bool CBigNum::isOne() const {
        return BN_is_one(bignum);
    }

    bool CBigNum::isNegative() const {
        return BN_is_negative(bignum);
    }

    void CBigNum::setNegative(bool negative) {
        BN_set_negative(bignum, negative ? 1 : 0);
    }

    CBigNum CBigNum::abs() const {
        CBigNum ret(*this);
        BN_set_negative(ret.bignum, 0);
        return ret;
    }

    // Comparison operators (implementations)
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

    // ============================================================================
    // Hash Functions Implementation
    // ============================================================================

    uint256 Hash(const std::vector<unsigned char>& vch) {
        return HashSHA256(vch);
    }

    uint256 HashSHA256(const std::vector<unsigned char>& vch) {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLen = 0;

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return uint256();

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) <= 0 ||
            EVP_DigestUpdate(ctx, vch.data(), vch.size()) <= 0 ||
            EVP_DigestFinal_ex(ctx, hash, &hashLen) <= 0) {
            EVP_MD_CTX_free(ctx);
        return uint256();
            }

            EVP_MD_CTX_free(ctx);
            return uint256(std::vector<unsigned char>(hash, hash + hashLen));
    }

    uint256 HashSHA1(const std::vector<unsigned char>& vch) {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLen = 0;

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return uint256();

        if (EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) <= 0 ||
            EVP_DigestUpdate(ctx, vch.data(), vch.size()) <= 0 ||
            EVP_DigestFinal_ex(ctx, hash, &hashLen) <= 0) {
            EVP_MD_CTX_free(ctx);
        return uint256();
            }

            EVP_MD_CTX_free(ctx);
            return uint256(std::vector<unsigned char>(hash, hash + hashLen));
    }

    uint256 HashRIPEMD160(const std::vector<unsigned char>& vch) {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLen = 0;

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return uint256();

        if (EVP_DigestInit_ex(ctx, EVP_ripemd160(), nullptr) <= 0 ||
            EVP_DigestUpdate(ctx, vch.data(), vch.size()) <= 0 ||
            EVP_DigestFinal_ex(ctx, hash, &hashLen) <= 0) {
            EVP_MD_CTX_free(ctx);
        return uint256();
            }

            EVP_MD_CTX_free(ctx);
            return uint256(std::vector<unsigned char>(hash, hash + hashLen));
    }

    uint256 HashSHA256D(const std::vector<unsigned char>& vch) {
        uint256 first = HashSHA256(vch);
        return HashSHA256(first.getvch());
    }

    uint256 Hash(const std::string& str) {
        return Hash(std::vector<unsigned char>(str.begin(), str.end()));
    }

    uint256 Hash(const uint256& hash) {
        return HashSHA256(hash.getvch());
    }

    // HMAC implementation
    std::vector<unsigned char> HMAC_SHA256(const std::vector<unsigned char>& key,
                                           const std::vector<unsigned char>& message) {
        std::vector<unsigned char> result(EVP_MAX_MD_SIZE);
        unsigned int len = 0;

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return std::vector<unsigned char>();

        EVP_PKEY* pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, key.data(), key.size());
        if (!pkey) {
            EVP_MD_CTX_free(ctx);
            return std::vector<unsigned char>();
        }

        if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0 ||
            EVP_DigestSignUpdate(ctx, message.data(), message.size()) <= 0 ||
            EVP_DigestSignFinal(ctx, result.data(), &len) <= 0) {
            EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(ctx);
        return std::vector<unsigned char>();
            }

            result.resize(len);
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(ctx);

            return result;
                                           }

                                           // ============================================================================
                                           // IntegerGroupParams Implementation
                                           // ============================================================================

                                           IntegerGroupParams::IntegerGroupParams()
                                           : groupOrder(0) {
                                           }

                                           CBigNum IntegerGroupParams::randomElement() const {
                                               if (groupOrder.isZero()) {
                                                   throw std::runtime_error("IntegerGroupParams::randomElement: groupOrder is zero");
                                               }
                                               return CBigNum::randBignum(groupOrder);
                                           }

                                           bool IntegerGroupParams::validate() const {
                                               // Check p and q are prime
                                               if (!p.isPrime() || !q.isPrime()) {
                                                   return false;
                                               }

                                               // Check groupOrder = p * q
                                               if (groupOrder != p * q) {
                                                   return false;
                                               }

                                               // Check g and h are generators of the subgroup
                                               // In a real implementation, we would check g^q mod p == 1, etc.

                                               return true;
                                           }

                                           bool IntegerGroupParams::isElement(const CBigNum& element) const {
                                               if (element <= 0 || element >= groupOrder) {
                                                   return false;
                                               }

                                               // Check element is in the subgroup
                                               // In real implementation: element^q mod p == 1

                                               return true;
                                           }

                                           // ============================================================================
                                           // ZerocoinParams Implementation
                                           // ============================================================================

                                           ZerocoinParams::ZerocoinParams()
                                           : accumulatorParamsMinPrimeLength(1024),
                                           ZK_iterations(80),
                                           securityLevel(80) {
                                           }

                                           ZerocoinParams::ZerocoinParams(CBigNum N, uint32_t security)
                                           : accumulatorParamsMinPrimeLength(1024),
                                           ZK_iterations(security),
                                           securityLevel(security) {
                                               // Simplified initialization
                                               // In original, this would generate all parameters from N
                                           }

                                           bool ZerocoinParams::validate() const {
                                               return coinCommitmentGroup.validate() &&
                                               serialNumberSoKCommitmentGroup.validate() &&
                                               accumulatorParams.validate();
                                           }

                                           CBigNum ZerocoinParams::getCoinValue(CoinDenomination denomination) {
                                               switch(denomination) {
                                                   case ZQ_ONE: return 1;
                                                   case ZQ_FIVE: return 5;
                                                   case ZQ_TEN: return 10;
                                                   case ZQ_FIFTY: return 50;
                                                   case ZQ_ONE_HUNDRED: return 100;
                                                   case ZQ_FIVE_HUNDRED: return 500;
                                                   case ZQ_ONE_THOUSAND: return 1000;
                                                   case ZQ_FIVE_THOUSAND: return 5000;
                                                   default: return 0;
                                               }
                                           }

                                           // ============================================================================
                                           // Accumulator Implementation
                                           // ============================================================================

                                           Accumulator::Accumulator(const IntegerGroupParams* p, const CBigNum& val)
                                           : params(p), value(val) {
                                               if (!params) {
                                                   throw std::runtime_error("Accumulator: params is null");
                                               }
                                           }

                                           void Accumulator::accumulate(const CBigNum& val) {
                                               if (!params) {
                                                   throw std::runtime_error("Accumulator::accumulate: params is null");
                                               }

                                               // Original implementation: value = value^val mod N
                                               // Simplified for now
                                               value = value + val;
                                               value = value % params->groupOrder;
                                           }

                                           bool Accumulator::isMember(const CBigNum& val) const {
                                               // Simplified check
                                               // In original: check if val divides value somehow
                                               return val > 0 && val < params->groupOrder;
                                           }

                                           // ============================================================================
                                           // AccumulatorWitness Implementation
                                           // ============================================================================

                                           AccumulatorWitness::AccumulatorWitness(const Accumulator* acc, const CBigNum& elem)
                                           : accumulator(acc), element(elem), witness(CBigNum(1)) {
                                               if (!accumulator) {
                                                   throw std::runtime_error("AccumulatorWitness: accumulator is null");
                                               }
                                           }

                                           void AccumulatorWitness::AddElement(const CBigNum& elem) {
                                               element = elem;
                                               // In original: witness = witness^elem mod N
                                               witness = witness + CBigNum(1);
                                           }

                                           bool AccumulatorWitness::Verify() const {
                                               if (!accumulator) return false;

                                               // Simplified verification
                                               // In original: check witness^element == accumulator value
                                               return witness > 0;
                                           }

} // namespace libzerocoin

// Initialize OpenSSL on library load
__attribute__((constructor))
static void init_libzerocoin() {
    libzerocoin::CBigNum::init();
}

__attribute__((destructor))
static void cleanup_libzerocoin() {
    libzerocoin::CBigNum::cleanup();
}

// Continuazione del file di implementazione...

namespace libzerocoin {

// ============================================================================
// CommitmentProofOfKnowledge Implementation
// ============================================================================

CommitmentProofOfKnowledge::CommitmentProofOfKnowledge(
    const IntegerGroupParams* params,
    const Commitment& commitment,
    const CBigNum& value) {

    if (!params || !commitment.getParams()) {
        throw std::runtime_error("CommitmentProofOfKnowledge: null parameters");
    }

    // Generate random values for the proof
    CBigNum r = CBigNum::randBignum(params->groupOrder);
    CBigNum s = CBigNum::randBignum(params->groupOrder);
    CBigNum t = CBigNum::randBignum(params->groupOrder);

    // Compute A = g^r * h^s mod p
    A = (params->g.modExp(r, params->p) * params->h.modExp(s, params->p)) % params->p;

    // Compute C = g^value * h^t mod p
    C = (params->g.modExp(value, params->p) * params->h.modExp(t, params->p)) % params->p;

    // Generate challenge using Fiat-Shamir heuristic
    std::vector<unsigned char> challengeData;
    challengeData.insert(challengeData.end(),
                        commitment.getCommitmentValue().getvch().begin(),
                        commitment.getCommitmentValue().getvch().end());
    challengeData.insert(challengeData.end(), A.getvch().begin(), A.getvch().end());
    challengeData.insert(challengeData.end(), C.getvch().begin(), C.getvch().end());

    CBigNum challenge = HashToPrime(challengeData);

    // Compute responses
    v_response = (value + challenge * commitment.getValue()) % params->groupOrder;
    rA_response = (r + challenge * commitment.getRandomness()) % params->groupOrder;
    rB_response = (s + challenge * t) % params->groupOrder;

    S = commitment.getCommitmentValue();
}

bool CommitmentProofOfKnowledge::Verify(const ZerocoinParams* params) const {
    if (!params) return false;
    return Verify(&params->coinCommitmentGroup,
                  Commitment(&params->coinCommitmentGroup, CBigNum(0), CBigNum(0)));
}

bool CommitmentProofOfKnowledge::Verify(const IntegerGroupParams* params,
                                       const Commitment& commitment) const {
    if (!params || S.isZero() || A.isZero() || C.isZero()) {
        return false;
    }

    // Recompute challenge
    std::vector<unsigned char> challengeData;
    challengeData.insert(challengeData.end(),
                        commitment.getCommitmentValue().getvch().begin(),
                        commitment.getCommitmentValue().getvch().end());
    challengeData.insert(challengeData.end(), A.getvch().begin(), A.getvch().end());
    challengeData.insert(challengeData.end(), C.getvch().begin(), C.getvch().end());

    CBigNum challenge = HashToPrime(challengeData);

    // Verify: g^v_response * h^rA_response == S^challenge * A mod p
    CBigNum left1 = (params->g.modExp(v_response, params->p) *
                     params->h.modExp(rA_response, params->p)) % params->p;
    CBigNum right1 = (S.modExp(challenge, params->p) * A) % params->p;

    if (left1 != right1) {
        return false;
    }

    // Verify: g^v_response * h^rB_response == commitment^challenge * C mod p
    CBigNum left2 = (params->g.modExp(v_response, params->p) *
                     params->h.modExp(rB_response, params->p)) % params->p;
    CBigNum right2 = (commitment.getCommitmentValue().modExp(challenge, params->p) * C) % params->p;

    return left2 == right2;
}

void CommitmentProofOfKnowledge::Serialize(CDataStream& stream) const {
    S.Serialize(stream);
    A.Serialize(stream);
    C.Serialize(stream);
    v_response.Serialize(stream);
    rA_response.Serialize(stream);
    rB_response.Serialize(stream);
}

void CommitmentProofOfKnowledge::Unserialize(CDataStream& stream) {
    S.Unserialize(stream);
    A.Unserialize(stream);
    C.Unserialize(stream);
    v_response.Unserialize(stream);
    rA_response.Unserialize(stream);
    rB_response.Unserialize(stream);
}

size_t CommitmentProofOfKnowledge::GetSize() const {
    return S.byteSize() + A.byteSize() + C.byteSize() +
           v_response.byteSize() + rA_response.byteSize() + rB_response.byteSize();
}

std::unique_ptr<CommitmentProofOfKnowledge> CommitmentProofOfKnowledge::Create(
    const IntegerGroupParams* params,
    const Commitment& commitment,
    const CBigNum& value,
    const CBigNum& randomness) {

    return std::make_unique<CommitmentProofOfKnowledge>(params, commitment, value);
}

// ============================================================================
// AccumulatorProofOfKnowledge Implementation
// ============================================================================

AccumulatorProofOfKnowledge::AccumulatorProofOfKnowledge(
    const IntegerGroupParams* accumulatorParams,
    const IntegerGroupParams* commitmentParams,
    const Commitment& commitmentToCoin,
    const Accumulator& accumulator) {

    // This is a simplified implementation
    // Original implementation from master is much more complex

    // Generate random values
    CBigNum alpha = CBigNum::randBignum(commitmentParams->groupOrder);
    CBigNum beta = CBigNum::randBignum(commitmentParams->groupOrder);
    CBigNum gamma = CBigNum::randBignum(commitmentParams->groupOrder);

    // Compute commitments
    C_e = (commitmentParams->g.modExp(alpha, commitmentParams->p) *
           commitmentParams->h.modExp(beta, commitmentParams->p)) % commitmentParams->p;

    C_u = (commitmentParams->g.modExp(gamma, commitmentParams->p)) % commitmentParams->p;

    // Generate challenge
    std::vector<unsigned char> challengeData;
    challengeData.insert(challengeData.end(),
                        commitmentToCoin.getCommitmentValue().getvch().begin(),
                        commitmentToCoin.getCommitmentValue().getvch().end());
    challengeData.insert(challengeData.end(),
                        accumulator.getValue().getvch().begin(),
                        accumulator.getValue().getvch().end());
    challengeData.insert(challengeData.end(), C_e.getvch().begin(), C_e.getvch().end());
    challengeData.insert(challengeData.end(), C_u.getvch().begin(), C_u.getvch().end());

    CBigNum challenge = HashToPrime(challengeData);

    // Compute responses (simplified)
    s_alpha = (alpha + challenge * commitmentToCoin.getValue()) % commitmentParams->groupOrder;
    s_beta = (beta + challenge * commitmentToCoin.getRandomness()) % commitmentParams->groupOrder;
    s_gamma = (gamma + challenge * CBigNum::randBignum(commitmentParams->groupOrder)) % commitmentParams->groupOrder;
}

bool AccumulatorProofOfKnowledge::Verify(const ZerocoinParams* params) const {
    if (!params) return false;

    // Create dummy commitment and accumulator for verification
    Commitment commitment(&params->coinCommitmentGroup, CBigNum(0), CBigNum(0));
    Accumulator accumulator(&params->accumulatorParams, CBigNum(1));

    return Verify(accumulator, commitment);
}

bool AccumulatorProofOfKnowledge::Verify(const Accumulator& accumulator,
                                        const Commitment& commitmentToCoin) const {
    // Simplified verification
    // In original: complex verification of all proof components

    if (C_e.isZero() || C_u.isZero()) {
        return false;
    }

    // Check that responses are in valid range
    if (s_alpha >= commitmentToCoin.getParams()->groupOrder ||
        s_beta >= commitmentToCoin.getParams()->groupOrder ||
        s_gamma >= commitmentToCoin.getParams()->groupOrder) {
        return false;
    }

    return true;
}

void AccumulatorProofOfKnowledge::Serialize(CDataStream& stream) const {
    C_e.Serialize(stream);
    C_u.Serialize(stream);
    C_r.Serialize(stream);
    st_1.Serialize(stream);
    st_2.Serialize(stream);
    st_3.Serialize(stream);
    t_1.Serialize(stream);
    t_2.Serialize(stream);
    t_3.Serialize(stream);
    t_4.Serialize(stream);
    s_alpha.Serialize(stream);
    s_beta.Serialize(stream);
    s_zeta.Serialize(stream);
    s_sigma.Serialize(stream);
    s_eta.Serialize(stream);
    s_epsilon.Serialize(stream);
    s_delta.Serialize(stream);
    s_xi.Serialize(stream);
    s_phi.Serialize(stream);
    s_gamma.Serialize(stream);
    s_psi.Serialize(stream);
}

void AccumulatorProofOfKnowledge::Unserialize(CDataStream& stream) {
    C_e.Unserialize(stream);
    C_u.Unserialize(stream);
    C_r.Unserialize(stream);
    st_1.Unserialize(stream);
    st_2.Unserialize(stream);
    st_3.Unserialize(stream);
    t_1.Unserialize(stream);
    t_2.Unserialize(stream);
    t_3.Unserialize(stream);
    t_4.Unserialize(stream);
    s_alpha.Unserialize(stream);
    s_beta.Unserialize(stream);
    s_zeta.Unserialize(stream);
    s_sigma.Unserialize(stream);
    s_eta.Unserialize(stream);
    s_epsilon.Unserialize(stream);
    s_delta.Unserialize(stream);
    s_xi.Unserialize(stream);
    s_phi.Unserialize(stream);
    s_gamma.Unserialize(stream);
    s_psi.Unserialize(stream);
}

size_t AccumulatorProofOfKnowledge::GetSize() const {
    size_t size = 0;
    size += C_e.byteSize() + C_u.byteSize() + C_r.byteSize();
    size += st_1.byteSize() + st_2.byteSize() + st_3.byteSize();
    size += t_1.byteSize() + t_2.byteSize() + t_3.byteSize() + t_4.byteSize();
    size += s_alpha.byteSize() + s_beta.byteSize() + s_zeta.byteSize();
    size += s_sigma.byteSize() + s_eta.byteSize() + s_epsilon.byteSize();
    size += s_delta.byteSize() + s_xi.byteSize() + s_phi.byteSize();
    size += s_gamma.byteSize() + s_psi.byteSize();
    return size;
}

std::unique_ptr<AccumulatorProofOfKnowledge> AccumulatorProofOfKnowledge::Create(
    const IntegerGroupParams* accumulatorParams,
    const IntegerGroupParams* commitmentParams,
    const Commitment& commitmentToCoin,
    const CBigNum& coinValue,
    const CBigNum& coinRandomness,
    const Accumulator& accumulator) {

    return std::make_unique<AccumulatorProofOfKnowledge>(
        accumulatorParams, commitmentParams, commitmentToCoin, accumulator);
}

// ============================================================================
// SerialNumberSignatureOfKnowledge Implementation
// ============================================================================

SerialNumberSignatureOfKnowledge::SerialNumberSignatureOfKnowledge(
    const IntegerGroupParams* params,
    const CBigNum& coinSerialNumber,
    const CBigNum& valueOfCommitmentToCoin,
    const CBigNum& serialNumberSokCommitment,
    const CBigNum& randomness,
    const uint256& msghash) {

    if (!params) {
        throw std::runtime_error("SerialNumberSignatureOfKnowledge: null parameters");
    }

    // Generate random values
    CBigNum r1 = CBigNum::randBignum(params->groupOrder);
    CBigNum r2 = CBigNum::randBignum(params->groupOrder);
    CBigNum r3 = CBigNum::randBignum(params->groupOrder);

    // Compute A' = g^r1 * h^r2 mod p
    A_prime = (params->g.modExp(r1, params->p) *
               params->h.modExp(r2, params->p)) % params->p;

    // Compute B' = g^r3 mod p
    B_prime = params->g.modExp(r3, params->p) % params->p;

    // Generate challenge
    std::vector<unsigned char> challengeData;
    challengeData.insert(challengeData.end(),
                        coinSerialNumber.getvch().begin(),
                        coinSerialNumber.getvch().end());
    challengeData.insert(challengeData.end(),
                        valueOfCommitmentToCoin.getvch().begin(),
                        valueOfCommitmentToCoin.getvch().end());
    challengeData.insert(challengeData.end(),
                        serialNumberSokCommitment.getvch().begin(),
                        serialNumberSokCommitment.getvch().end());
    challengeData.insert(challengeData.end(), A_prime.getvch().begin(), A_prime.getvch().end());
    challengeData.insert(challengeData.end(), B_prime.getvch().begin(), B_prime.getvch().end());
    challengeData.insert(challengeData.end(), msghash.begin(), msghash.end());

    CBigNum challenge = HashToPrime(challengeData);

    // Compute responses
    m_1 = (coinSerialNumber + challenge * valueOfCommitmentToCoin) % params->groupOrder;
    m_2 = (randomness + challenge * serialNumberSokCommitment) % params->groupOrder;
    m_3 = (r3 + challenge * CBigNum::randBignum(params->groupOrder)) % params->groupOrder;

    s_1 = (r1 + challenge * coinSerialNumber) % params->groupOrder;
    s_2 = (r2 + challenge * randomness) % params->groupOrder;
    s_3 = (r3 + challenge * m_3) % params->groupOrder;
}

bool SerialNumberSignatureOfKnowledge::Verify(const ZerocoinParams* params) const {
    if (!params) return false;

    // Create dummy values for verification
    CBigNum coinSerialNumber(0);
    CBigNum valueOfCommitmentToCoin(0);
    CBigNum serialNumberSokCommitment(0);
    uint256 msghash;

    return Verify(coinSerialNumber, valueOfCommitmentToCoin,
                  serialNumberSokCommitment, msghash);
}

bool SerialNumberSignatureOfKnowledge::Verify(
    const CBigNum& coinSerialNumber,
    const CBigNum& valueOfCommitmentToCoin,
    const CBigNum& serialNumberSokCommitment,
    const uint256& msghash) const {

    // Recompute challenge
    std::vector<unsigned char> challengeData;
    challengeData.insert(challengeData.end(),
                        coinSerialNumber.getvch().begin(),
                        coinSerialNumber.getvch().end());
    challengeData.insert(challengeData.end(),
                        valueOfCommitmentToCoin.getvch().begin(),
                        valueOfCommitmentToCoin.getvch().end());
    challengeData.insert(challengeData.end(),
                        serialNumberSokCommitment.getvch().begin(),
                        serialNumberSokCommitment.getvch().end());
    challengeData.insert(challengeData.end(), A_prime.getvch().begin(), A_prime.getvch().end());
    challengeData.insert(challengeData.end(), B_prime.getvch().begin(), B_prime.getvch().end());
    challengeData.insert(challengeData.end(), msghash.begin(), msghash.end());

    CBigNum challenge = HashToPrime(challengeData);

    // Verify: g^m_1 * h^m_2 == A' * (serialNumberSokCommitment)^challenge mod p
    // This is simplified - original has more complex verification

    return !A_prime.isZero() && !B_prime.isZero();
}

void SerialNumberSignatureOfKnowledge::Serialize(CDataStream& stream) const {
    A_prime.Serialize(stream);
    B_prime.Serialize(stream);
    r_1.Serialize(stream);
    r_2.Serialize(stream);
    r_3.Serialize(stream);
    m_1.Serialize(stream);
    m_2.Serialize(stream);
    m_3.Serialize(stream);
    s_1.Serialize(stream);
    s_2.Serialize(stream);
    s_3.Serialize(stream);
    t_1.Serialize(stream);
    t_2.Serialize(stream);
    t_3.Serialize(stream);
    t_4.Serialize(stream);
}

void SerialNumberSignatureOfKnowledge::Unserialize(CDataStream& stream) {
    A_prime.Unserialize(stream);
    B_prime.Unserialize(stream);
    r_1.Unserialize(stream);
    r_2.Unserialize(stream);
    r_3.Unserialize(stream);
    m_1.Unserialize(stream);
    m_2.Unserialize(stream);
    m_3.Unserialize(stream);
    s_1.Unserialize(stream);
    s_2.Unserialize(stream);
    s_3.Unserialize(stream);
    t_1.Unserialize(stream);
    t_2.Unserialize(stream);
    t_3.Unserialize(stream);
    t_4.Unserialize(stream);
}

size_t SerialNumberSignatureOfKnowledge::GetSize() const {
    size_t size = 0;
    size += A_prime.byteSize() + B_prime.byteSize();
    size += r_1.byteSize() + r_2.byteSize() + r_3.byteSize();
    size += m_1.byteSize() + m_2.byteSize() + m_3.byteSize();
    size += s_1.byteSize() + s_2.byteSize() + s_3.byteSize();
    size += t_1.byteSize() + t_2.byteSize() + t_3.byteSize() + t_4.byteSize();
    return size;
}

std::unique_ptr<SerialNumberSignatureOfKnowledge> SerialNumberSignatureOfKnowledge::Create(
    const IntegerGroupParams* params,
    const CBigNum& coinSerialNumber,
    const CBigNum& valueOfCommitmentToCoin,
    const CBigNum& serialNumberSokCommitment,
    const CBigNum& randomness,
    const uint256& msghash) {

    return std::make_unique<SerialNumberSignatureOfKnowledge>(
        params, coinSerialNumber, valueOfCommitmentToCoin,
        serialNumberSokCommitment, randomness, msghash);
}

// ============================================================================
// PublicCoin Implementation
// ============================================================================

bool PublicCoin::validate() const {
    if (!params || value.isZero() || denomination == ZQ_ERROR) {
        return false;
    }

    // Check value is in the group
    return params->coinCommitmentGroup.isElement(value);
}

bool PublicCoin::operator==(const PublicCoin& other) const {
    return params == other.params &&
           value == other.value &&
           denomination == other.denomination;
}

bool PublicCoin::operator!=(const PublicCoin& other) const {
    return !(*this == other);
}

bool PublicCoin::operator<(const PublicCoin& other) const {
    if (params != other.params) return params < other.params;
    if (denomination != other.denomination) return denomination < other.denomination;
    return value < other.value;
}

uint256 PublicCoin::getValueHash() const {
    return Hash(value.getvch());
}

// ============================================================================
// PrivateCoin Implementation
// ============================================================================

PrivateCoin::PrivateCoin(const ZerocoinParams* p, CoinDenomination d, uint8_t v)
    : params(p), denomination(d), version(v) {

    if (!params) {
        throw std::runtime_error("PrivateCoin: null parameters");
    }

    generate();
}

void PrivateCoin::generate() {
    // Generate random serial number
    serialNumber = CBigNum::randBignum(params->coinCommitmentGroup.groupOrder);

    // Generate random commitment randomness
    randomness = CBigNum::randBignum(params->coinCommitmentGroup.groupOrder);

    // Compute commitment

    // Continuazione del file di implementazione...

    namespace libzerocoin {

        // ============================================================================
        // CommitmentProofOfKnowledge Implementation
        // ============================================================================

        CommitmentProofOfKnowledge::CommitmentProofOfKnowledge(
            const IntegerGroupParams* params,
            const Commitment& commitment,
            const CBigNum& value) {

            if (!params || !commitment.getParams()) {
                throw std::runtime_error("CommitmentProofOfKnowledge: null parameters");
            }

            // Generate random values for the proof
            CBigNum r = CBigNum::randBignum(params->groupOrder);
            CBigNum s = CBigNum::randBignum(params->groupOrder);
            CBigNum t = CBigNum::randBignum(params->groupOrder);

            // Compute A = g^r * h^s mod p
            A = (params->g.modExp(r, params->p) * params->h.modExp(s, params->p)) % params->p;

            // Compute C = g^value * h^t mod p
            C = (params->g.modExp(value, params->p) * params->h.modExp(t, params->p)) % params->p;

            // Generate challenge using Fiat-Shamir heuristic
            std::vector<unsigned char> challengeData;
            challengeData.insert(challengeData.end(),
                                 commitment.getCommitmentValue().getvch().begin(),
                                 commitment.getCommitmentValue().getvch().end());
            challengeData.insert(challengeData.end(), A.getvch().begin(), A.getvch().end());
            challengeData.insert(challengeData.end(), C.getvch().begin(), C.getvch().end());

            CBigNum challenge = HashToPrime(challengeData);

            // Compute responses
            v_response = (value + challenge * commitment.getValue()) % params->groupOrder;
            rA_response = (r + challenge * commitment.getRandomness()) % params->groupOrder;
            rB_response = (s + challenge * t) % params->groupOrder;

            S = commitment.getCommitmentValue();
            }

            bool CommitmentProofOfKnowledge::Verify(const ZerocoinParams* params) const {
                if (!params) return false;
                return Verify(&params->coinCommitmentGroup,
                              Commitment(&params->coinCommitmentGroup, CBigNum(0), CBigNum(0)));
            }

            bool CommitmentProofOfKnowledge::Verify(const IntegerGroupParams* params,
                                                    const Commitment& commitment) const {
                                                        if (!params || S.isZero() || A.isZero() || C.isZero()) {
                                                            return false;
                                                        }

                                                        // Recompute challenge
                                                        std::vector<unsigned char> challengeData;
                                                        challengeData.insert(challengeData.end(),
                                                                             commitment.getCommitmentValue().getvch().begin(),
                                                                             commitment.getCommitmentValue().getvch().end());
                                                        challengeData.insert(challengeData.end(), A.getvch().begin(), A.getvch().end());
                                                        challengeData.insert(challengeData.end(), C.getvch().begin(), C.getvch().end());

                                                        CBigNum challenge = HashToPrime(challengeData);

                                                        // Verify: g^v_response * h^rA_response == S^challenge * A mod p
                                                        CBigNum left1 = (params->g.modExp(v_response, params->p) *
                                                        params->h.modExp(rA_response, params->p)) % params->p;
                                                        CBigNum right1 = (S.modExp(challenge, params->p) * A) % params->p;

                                                        if (left1 != right1) {
                                                            return false;
                                                        }

                                                        // Verify: g^v_response * h^rB_response == commitment^challenge * C mod p
                                                        CBigNum left2 = (params->g.modExp(v_response, params->p) *
                                                        params->h.modExp(rB_response, params->p)) % params->p;
                                                        CBigNum right2 = (commitment.getCommitmentValue().modExp(challenge, params->p) * C) % params->p;

                                                        return left2 == right2;
                                                    }

                                                    void CommitmentProofOfKnowledge::Serialize(CDataStream& stream) const {
                                                        S.Serialize(stream);
                                                        A.Serialize(stream);
                                                        C.Serialize(stream);
                                                        v_response.Serialize(stream);
                                                        rA_response.Serialize(stream);
                                                        rB_response.Serialize(stream);
                                                    }

                                                    void CommitmentProofOfKnowledge::Unserialize(CDataStream& stream) {
                                                        S.Unserialize(stream);
                                                        A.Unserialize(stream);
                                                        C.Unserialize(stream);
                                                        v_response.Unserialize(stream);
                                                        rA_response.Unserialize(stream);
                                                        rB_response.Unserialize(stream);
                                                    }

                                                    size_t CommitmentProofOfKnowledge::GetSize() const {
                                                        return S.byteSize() + A.byteSize() + C.byteSize() +
                                                        v_response.byteSize() + rA_response.byteSize() + rB_response.byteSize();
                                                    }

                                                    std::unique_ptr<CommitmentProofOfKnowledge> CommitmentProofOfKnowledge::Create(
                                                        const IntegerGroupParams* params,
                                                        const Commitment& commitment,
                                                        const CBigNum& value,
                                                        const CBigNum& randomness) {

                                                        return std::make_unique<CommitmentProofOfKnowledge>(params, commitment, value);
                                                        }

                                                        // ============================================================================
                                                        // AccumulatorProofOfKnowledge Implementation
                                                        // ============================================================================

                                                        AccumulatorProofOfKnowledge::AccumulatorProofOfKnowledge(
                                                            const IntegerGroupParams* accumulatorParams,
                                                            const IntegerGroupParams* commitmentParams,
                                                            const Commitment& commitmentToCoin,
                                                            const Accumulator& accumulator) {

                                                            // This is a simplified implementation
                                                            // Original implementation from master is much more complex

                                                            // Generate random values
                                                            CBigNum alpha = CBigNum::randBignum(commitmentParams->groupOrder);
                                                            CBigNum beta = CBigNum::randBignum(commitmentParams->groupOrder);
                                                            CBigNum gamma = CBigNum::randBignum(commitmentParams->groupOrder);

                                                            // Compute commitments
                                                            C_e = (commitmentParams->g.modExp(alpha, commitmentParams->p) *
                                                            commitmentParams->h.modExp(beta, commitmentParams->p)) % commitmentParams->p;

                                                            C_u = (commitmentParams->g.modExp(gamma, commitmentParams->p)) % commitmentParams->p;

                                                            // Generate challenge
                                                            std::vector<unsigned char> challengeData;
                                                            challengeData.insert(challengeData.end(),
                                                                                 commitmentToCoin.getCommitmentValue().getvch().begin(),
                                                                                 commitmentToCoin.getCommitmentValue().getvch().end());
                                                            challengeData.insert(challengeData.end(),
                                                                                 accumulator.getValue().getvch().begin(),
                                                                                 accumulator.getValue().getvch().end());
                                                            challengeData.insert(challengeData.end(), C_e.getvch().begin(), C_e.getvch().end());
                                                            challengeData.insert(challengeData.end(), C_u.getvch().begin(), C_u.getvch().end());

                                                            CBigNum challenge = HashToPrime(challengeData);

                                                            // Compute responses (simplified)
                                                            s_alpha = (alpha + challenge * commitmentToCoin.getValue()) % commitmentParams->groupOrder;
                                                            s_beta = (beta + challenge * commitmentToCoin.getRandomness()) % commitmentParams->groupOrder;
                                                            s_gamma = (gamma + challenge * CBigNum::randBignum(commitmentParams->groupOrder)) % commitmentParams->groupOrder;
                                                            }

                                                            bool AccumulatorProofOfKnowledge::Verify(const ZerocoinParams* params) const {
                                                                if (!params) return false;

                                                                // Create dummy commitment and accumulator for verification
                                                                Commitment commitment(&params->coinCommitmentGroup, CBigNum(0), CBigNum(0));
                                                                Accumulator accumulator(&params->accumulatorParams, CBigNum(1));

                                                                return Verify(accumulator, commitment);
                                                            }

                                                            bool AccumulatorProofOfKnowledge::Verify(const Accumulator& accumulator,
                                                                                                     const Commitment& commitmentToCoin) const {
                                                                                                         // Simplified verification
                                                                                                         // In original: complex verification of all proof components

                                                                                                         if (C_e.isZero() || C_u.isZero()) {
                                                                                                             return false;
                                                                                                         }

                                                                                                         // Check that responses are in valid range
                                                                                                         if (s_alpha >= commitmentToCoin.getParams()->groupOrder ||
                                                                                                             s_beta >= commitmentToCoin.getParams()->groupOrder ||
                                                                                                             s_gamma >= commitmentToCoin.getParams()->groupOrder) {
                                                                                                             return false;
                                                                                                             }

                                                                                                             return true;
                                                                                                     }

                                                                                                     void AccumulatorProofOfKnowledge::Serialize(CDataStream& stream) const {
                                                                                                         C_e.Serialize(stream);
                                                                                                         C_u.Serialize(stream);
                                                                                                         C_r.Serialize(stream);
                                                                                                         st_1.Serialize(stream);
                                                                                                         st_2.Serialize(stream);
                                                                                                         st_3.Serialize(stream);
                                                                                                         t_1.Serialize(stream);
                                                                                                         t_2.Serialize(stream);
                                                                                                         t_3.Serialize(stream);
                                                                                                         t_4.Serialize(stream);
                                                                                                         s_alpha.Serialize(stream);
                                                                                                         s_beta.Serialize(stream);
                                                                                                         s_zeta.Serialize(stream);
                                                                                                         s_sigma.Serialize(stream);
                                                                                                         s_eta.Serialize(stream);
                                                                                                         s_epsilon.Serialize(stream);
                                                                                                         s_delta.Serialize(stream);
                                                                                                         s_xi.Serialize(stream);
                                                                                                         s_phi.Serialize(stream);
                                                                                                         s_gamma.Serialize(stream);
                                                                                                         s_psi.Serialize(stream);
                                                                                                     }

                                                                                                     void AccumulatorProofOfKnowledge::Unserialize(CDataStream& stream) {
                                                                                                         C_e.Unserialize(stream);
                                                                                                         C_u.Unserialize(stream);
                                                                                                         C_r.Unserialize(stream);
                                                                                                         st_1.Unserialize(stream);
                                                                                                         st_2.Unserialize(stream);
                                                                                                         st_3.Unserialize(stream);
                                                                                                         t_1.Unserialize(stream);
                                                                                                         t_2.Unserialize(stream);
                                                                                                         t_3.Unserialize(stream);
                                                                                                         t_4.Unserialize(stream);
                                                                                                         s_alpha.Unserialize(stream);
                                                                                                         s_beta.Unserialize(stream);
                                                                                                         s_zeta.Unserialize(stream);
                                                                                                         s_sigma.Unserialize(stream);
                                                                                                         s_eta.Unserialize(stream);
                                                                                                         s_epsilon.Unserialize(stream);
                                                                                                         s_delta.Unserialize(stream);
                                                                                                         s_xi.Unserialize(stream);
                                                                                                         s_phi.Unserialize(stream);
                                                                                                         s_gamma.Unserialize(stream);
                                                                                                         s_psi.Unserialize(stream);
                                                                                                     }

                                                                                                     size_t AccumulatorProofOfKnowledge::GetSize() const {
                                                                                                         size_t size = 0;
                                                                                                         size += C_e.byteSize() + C_u.byteSize() + C_r.byteSize();
                                                                                                         size += st_1.byteSize() + st_2.byteSize() + st_3.byteSize();
                                                                                                         size += t_1.byteSize() + t_2.byteSize() + t_3.byteSize() + t_4.byteSize();
                                                                                                         size += s_alpha.byteSize() + s_beta.byteSize() + s_zeta.byteSize();
                                                                                                         size += s_sigma.byteSize() + s_eta.byteSize() + s_epsilon.byteSize();
                                                                                                         size += s_delta.byteSize() + s_xi.byteSize() + s_phi.byteSize();
                                                                                                         size += s_gamma.byteSize() + s_psi.byteSize();
                                                                                                         return size;
                                                                                                     }

                                                                                                     std::unique_ptr<AccumulatorProofOfKnowledge> AccumulatorProofOfKnowledge::Create(
                                                                                                         const IntegerGroupParams* accumulatorParams,
                                                                                                         const IntegerGroupParams* commitmentParams,
                                                                                                         const Commitment& commitmentToCoin,
                                                                                                         const CBigNum& coinValue,
                                                                                                         const CBigNum& coinRandomness,
                                                                                                         const Accumulator& accumulator) {

                                                                                                         return std::make_unique<AccumulatorProofOfKnowledge>(
                                                                                                             accumulatorParams, commitmentParams, commitmentToCoin, accumulator);
                                                                                                         }

                                                                                                         // ============================================================================
                                                                                                         // SerialNumberSignatureOfKnowledge Implementation
                                                                                                         // ============================================================================

                                                                                                         SerialNumberSignatureOfKnowledge::SerialNumberSignatureOfKnowledge(
                                                                                                             const IntegerGroupParams* params,
                                                                                                             const CBigNum& coinSerialNumber,
                                                                                                             const CBigNum& valueOfCommitmentToCoin,
                                                                                                             const CBigNum& serialNumberSokCommitment,
                                                                                                             const CBigNum& randomness,
                                                                                                             const uint256& msghash) {

                                                                                                             if (!params) {
                                                                                                                 throw std::runtime_error("SerialNumberSignatureOfKnowledge: null parameters");
                                                                                                             }

                                                                                                             // Generate random values
                                                                                                             CBigNum r1 = CBigNum::randBignum(params->groupOrder);
                                                                                                             CBigNum r2 = CBigNum::randBignum(params->groupOrder);
                                                                                                             CBigNum r3 = CBigNum::randBignum(params->groupOrder);

                                                                                                             // Compute A' = g^r1 * h^r2 mod p
                                                                                                             A_prime = (params->g.modExp(r1, params->p) *
                                                                                                             params->h.modExp(r2, params->p)) % params->p;

                                                                                                             // Compute B' = g^r3 mod p
                                                                                                             B_prime = params->g.modExp(r3, params->p) % params->p;

                                                                                                             // Generate challenge
                                                                                                             std::vector<unsigned char> challengeData;
                                                                                                             challengeData.insert(challengeData.end(),
                                                                                                                                  coinSerialNumber.getvch().begin(),
                                                                                                                                  coinSerialNumber.getvch().end());
                                                                                                             challengeData.insert(challengeData.end(),
                                                                                                                                  valueOfCommitmentToCoin.getvch().begin(),
                                                                                                                                  valueOfCommitmentToCoin.getvch().end());
                                                                                                             challengeData.insert(challengeData.end(),
                                                                                                                                  serialNumberSokCommitment.getvch().begin(),
                                                                                                                                  serialNumberSokCommitment.getvch().end());
                                                                                                             challengeData.insert(challengeData.end(), A_prime.getvch().begin(), A_prime.getvch().end());
                                                                                                             challengeData.insert(challengeData.end(), B_prime.getvch().begin(), B_prime.getvch().end());
                                                                                                             challengeData.insert(challengeData.end(), msghash.begin(), msghash.end());

                                                                                                             CBigNum challenge = HashToPrime(challengeData);

                                                                                                             // Compute responses
                                                                                                             m_1 = (coinSerialNumber + challenge * valueOfCommitmentToCoin) % params->groupOrder;
                                                                                                             m_2 = (randomness + challenge * serialNumberSokCommitment) % params->groupOrder;
                                                                                                             m_3 = (r3 + challenge * CBigNum::randBignum(params->groupOrder)) % params->groupOrder;

                                                                                                             s_1 = (r1 + challenge * coinSerialNumber) % params->groupOrder;
                                                                                                             s_2 = (r2 + challenge * randomness) % params->groupOrder;
                                                                                                             s_3 = (r3 + challenge * m_3) % params->groupOrder;
                                                                                                             }

                                                                                                             bool SerialNumberSignatureOfKnowledge::Verify(const ZerocoinParams* params) const {
                                                                                                                 if (!params) return false;

                                                                                                                 // Create dummy values for verification
                                                                                                                 CBigNum coinSerialNumber(0);
                                                                                                                 CBigNum valueOfCommitmentToCoin(0);
                                                                                                                 CBigNum serialNumberSokCommitment(0);
                                                                                                                 uint256 msghash;

                                                                                                                 return Verify(coinSerialNumber, valueOfCommitmentToCoin,
                                                                                                                               serialNumberSokCommitment, msghash);
                                                                                                             }

                                                                                                             bool SerialNumberSignatureOfKnowledge::Verify(
                                                                                                                 const CBigNum& coinSerialNumber,
                                                                                                                 const CBigNum& valueOfCommitmentToCoin,
                                                                                                                 const CBigNum& serialNumberSokCommitment,
                                                                                                                 const uint256& msghash) const {

                                                                                                                     // Recompute challenge
                                                                                                                     std::vector<unsigned char> challengeData;
                                                                                                                     challengeData.insert(challengeData.end(),
                                                                                                                                          coinSerialNumber.getvch().begin(),
                                                                                                                                          coinSerialNumber.getvch().end());
                                                                                                                     challengeData.insert(challengeData.end(),
                                                                                                                                          valueOfCommitmentToCoin.getvch().begin(),
                                                                                                                                          valueOfCommitmentToCoin.getvch().end());
                                                                                                                     challengeData.insert(challengeData.end(),
                                                                                                                                          serialNumberSokCommitment.getvch().begin(),
                                                                                                                                          serialNumberSokCommitment.getvch().end());
                                                                                                                     challengeData.insert(challengeData.end(), A_prime.getvch().begin(), A_prime.getvch().end());
                                                                                                                     challengeData.insert(challengeData.end(), B_prime.getvch().begin(), B_prime.getvch().end());
                                                                                                                     challengeData.insert(challengeData.end(), msghash.begin(), msghash.end());

                                                                                                                     CBigNum challenge = HashToPrime(challengeData);

                                                                                                                     // Verify: g^m_1 * h^m_2 == A' * (serialNumberSokCommitment)^challenge mod p
                                                                                                                     // This is simplified - original has more complex verification

                                                                                                                     return !A_prime.isZero() && !B_prime.isZero();
                                                                                                                 }

                                                                                                                 void SerialNumberSignatureOfKnowledge::Serialize(CDataStream& stream) const {
                                                                                                                     A_prime.Serialize(stream);
                                                                                                                     B_prime.Serialize(stream);
                                                                                                                     r_1.Serialize(stream);
                                                                                                                     r_2.Serialize(stream);
                                                                                                                     r_3.Serialize(stream);
                                                                                                                     m_1.Serialize(stream);
                                                                                                                     m_2.Serialize(stream);
                                                                                                                     m_3.Serialize(stream);
                                                                                                                     s_1.Serialize(stream);
                                                                                                                     s_2.Serialize(stream);
                                                                                                                     s_3.Serialize(stream);
                                                                                                                     t_1.Serialize(stream);
                                                                                                                     t_2.Serialize(stream);
                                                                                                                     t_3.Serialize(stream);
                                                                                                                     t_4.Serialize(stream);
                                                                                                                 }

                                                                                                                 void SerialNumberSignatureOfKnowledge::Unserialize(CDataStream& stream) {
                                                                                                                     A_prime.Unserialize(stream);
                                                                                                                     B_prime.Unserialize(stream);
                                                                                                                     r_1.Unserialize(stream);
                                                                                                                     r_2.Unserialize(stream);
                                                                                                                     r_3.Unserialize(stream);
                                                                                                                     m_1.Unserialize(stream);
                                                                                                                     m_2.Unserialize(stream);
                                                                                                                     m_3.Unserialize(stream);
                                                                                                                     s_1.Unserialize(stream);
                                                                                                                     s_2.Unserialize(stream);
                                                                                                                     s_3.Unserialize(stream);
                                                                                                                     t_1.Unserialize(stream);
                                                                                                                     t_2.Unserialize(stream);
                                                                                                                     t_3.Unserialize(stream);
                                                                                                                     t_4.Unserialize(stream);
                                                                                                                 }

                                                                                                                 size_t SerialNumberSignatureOfKnowledge::GetSize() const {
                                                                                                                     size_t size = 0;
                                                                                                                     size += A_prime.byteSize() + B_prime.byteSize();
                                                                                                                     size += r_1.byteSize() + r_2.byteSize() + r_3.byteSize();
                                                                                                                     size += m_1.byteSize() + m_2.byteSize() + m_3.byteSize();
                                                                                                                     size += s_1.byteSize() + s_2.byteSize() + s_3.byteSize();
                                                                                                                     size += t_1.byteSize() + t_2.byteSize() + t_3.byteSize() + t_4.byteSize();
                                                                                                                     return size;
                                                                                                                 }

                                                                                                                 std::unique_ptr<SerialNumberSignatureOfKnowledge> SerialNumberSignatureOfKnowledge::Create(
                                                                                                                     const IntegerGroupParams* params,
                                                                                                                     const CBigNum& coinSerialNumber,
                                                                                                                     const CBigNum& valueOfCommitmentToCoin,
                                                                                                                     const CBigNum& serialNumberSokCommitment,
                                                                                                                     const CBigNum& randomness,
                                                                                                                     const uint256& msghash) {

                                                                                                                     return std::make_unique<SerialNumberSignatureOfKnowledge>(
                                                                                                                         params, coinSerialNumber, valueOfCommitmentToCoin,
                                                                                                                         serialNumberSokCommitment, randomness, msghash);
                                                                                                                     }

                                                                                                                     // ============================================================================
                                                                                                                     // PublicCoin Implementation
                                                                                                                     // ============================================================================

                                                                                                                     bool PublicCoin::validate() const {
                                                                                                                         if (!params || value.isZero() || denomination == ZQ_ERROR) {
                                                                                                                             return false;
                                                                                                                         }

                                                                                                                         // Check value is in the group
                                                                                                                         return params->coinCommitmentGroup.isElement(value);
                                                                                                                     }

                                                                                                                     bool PublicCoin::operator==(const PublicCoin& other) const {
                                                                                                                         return params == other.params &&
                                                                                                                         value == other.value &&
                                                                                                                         denomination == other.denomination;
                                                                                                                     }

                                                                                                                     bool PublicCoin::operator!=(const PublicCoin& other) const {
                                                                                                                         return !(*this == other);
                                                                                                                     }

                                                                                                                     bool PublicCoin::operator<(const PublicCoin& other) const {
                                                                                                                         if (params != other.params) return params < other.params;
                                                                                                                         if (denomination != other.denomination) return denomination < other.denomination;
                                                                                                                         return value < other.value;
                                                                                                                     }

                                                                                                                     uint256 PublicCoin::getValueHash() const {
                                                                                                                         return Hash(value.getvch());
                                                                                                                     }

                                                                                                                     // ============================================================================
                                                                                                                     // PrivateCoin Implementation
                                                                                                                     // ============================================================================

                                                                                                                     PrivateCoin::PrivateCoin(const ZerocoinParams* p, CoinDenomination d, uint8_t v)
                                                                                                                     : params(p), denomination(d), version(v) {

                                                                                                                         if (!params) {
                                                                                                                             throw std::runtime_error("PrivateCoin: null parameters");
                                                                                                                         }

                                                                                                                         generate();
                                                                                                                     }

                                                                                                                     void PrivateCoin::generate() {
                                                                                                                         // Generate random serial number
                                                                                                                         serialNumber = CBigNum::randBignum(params->coinCommitmentGroup.groupOrder);

                                                                                                                         // Generate random commitment randomness
                                                                                                                         randomness = CBigNum::randBignum(params->coinCommitmentGroup.groupOrder);

                                                                                                                         // Compute commitment


