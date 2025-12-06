// libzerocoin.hpp - Versione C++20 corretta
#pragma once

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <memory>
#include <vector>
#include <string>
#include <array>
#include <span>
#include <concepts>
#include <ranges>
#include <format>
#include <random>  // AGGIUNTO
#include <source_location>
#include <stdexcept>
#include <cstdint>
#include <algorithm>
#include <numeric>
#include <functional>

namespace libzerocoin {


    // ============================================================================
    // CONSTANTS & CONFIG (C++20 style)
    // ============================================================================

    constexpr uint32_t ZEROCOIN_DEFAULT_SECURITYLEVEL = 80;
    constexpr uint32_t ZEROCOIN_VERSION_1 = 1;
    constexpr uint32_t ZEROCOIN_VERSION_2 = 2;

    enum class CoinDenomination : uint64_t {
        ZQ_ERROR = 0,
        ZQ_ONE = 1,
        ZQ_FIVE = 5,
        ZQ_TEN = 10,
        ZQ_FIFTY = 50,
        ZQ_ONE_HUNDRED = 100,
        ZQ_FIVE_HUNDRED = 500,
        ZQ_ONE_THOUSAND = 1000,
        ZQ_FIVE_THOUSAND = 5000
    };

    // ============================================================================
    // MODERN BIGNUM WRAPPER (C++20 RAII)
    // ============================================================================

    class BigNum {
    private:
        BIGNUM* bn{nullptr};

    public:
        // Costruttori
        BigNum() : bn(BN_new()) {
            if (!bn) throw std::bad_alloc();
        }

        explicit BigNum(const std::string& hex) : bn(nullptr) {
            BN_hex2bn(&bn, hex.c_str());
            if (!bn) throw std::runtime_error("Invalid hex string");
        }

        explicit BigNum(uint64_t value) : bn(BN_new()) {
            if (!bn) throw std::bad_alloc();
            BN_set_word(bn, value);
        }

        // Rule of Five
        BigNum(const BigNum& other) : bn(BN_dup(other.bn)) {
            if (!bn) throw std::bad_alloc();
        }

        BigNum(BigNum&& other) noexcept : bn(other.bn) {
            other.bn = nullptr;
        }

        BigNum& operator=(const BigNum& other) {
            if (this != &other) {
                BIGNUM* new_bn = BN_dup(other.bn);
                if (!new_bn) throw std::bad_alloc();
                BN_free(bn);
                bn = new_bn;
            }
            return *this;
        }

        BigNum& operator=(BigNum&& other) noexcept {
            if (this != &other) {
                BN_free(bn);
                bn = other.bn;
                other.bn = nullptr;
            }
            return *this;
        }

        ~BigNum() {
            BN_free(bn);
        }

        // Conversioni
        [[nodiscard]] std::string toHex() const {
            char* hex = BN_bn2hex(bn);
            if (!hex) throw std::runtime_error("BN_bn2hex failed");
            std::string result(hex);
            OPENSSL_free(hex);
            return result;
        }

        [[nodiscard]] std::vector<uint8_t> toBytes() const {
            std::vector<uint8_t> bytes(BN_num_bytes(bn));
            BN_bn2bin(bn, bytes.data());
            return bytes;
        }

        // Operatori aritmetici
        BigNum operator+(const BigNum& other) const {
            BigNum result;
            if (!BN_add(result.bn, bn, other.bn)) {
                throw std::runtime_error("BN_add failed");
            }
            return result;
        }

        BigNum operator*(const BigNum& other) const {
            BigNum result;
            BN_CTX* ctx = BN_CTX_new();
            if (!ctx) throw std::bad_alloc();

            if (!BN_mul(result.bn, bn, other.bn, ctx)) {
                BN_CTX_free(ctx);
                throw std::runtime_error("BN_mul failed");
            }
            BN_CTX_free(ctx);
            return result;
        }

        BigNum modExp(const BigNum& exp, const BigNum& mod) const {
            BigNum result;
            BN_CTX* ctx = BN_CTX_new();
            if (!ctx) throw std::bad_alloc();

            if (!BN_mod_exp(result.bn, bn, exp.bn, mod.bn, ctx)) {
                BN_CTX_free(ctx);
                throw std::runtime_error("BN_mod_exp failed");
            }
            BN_CTX_free(ctx);
            return result;
        }

        // Mod inverse
        [[nodiscard]] BigNum modInverse(const BigNum& mod) const {
            BigNum result;
            BN_CTX* ctx = BN_CTX_new();
            if (!ctx) throw std::bad_alloc();

            if (!BN_mod_inverse(result.bn, bn, mod.bn, ctx)) {
                BN_CTX_free(ctx);
                throw std::runtime_error("BN_mod_inverse failed");
            }
            BN_CTX_free(ctx);
            return result;
        }

        // Comparatori
        [[nodiscard]] bool operator==(const BigNum& other) const {
            return BN_cmp(bn, other.bn) == 0;
        }

        [[nodiscard]] bool operator!=(const BigNum& other) const {
            return !(*this == other);
        }

        [[nodiscard]] bool operator<(const BigNum& other) const {
            return BN_cmp(bn, other.bn) < 0;
        }

        [[nodiscard]] bool isZero() const {
            return BN_is_zero(bn);
        }

        [[nodiscard]] bool isOne() const {
            return BN_is_one(bn);
        }

        // Random generation (C++20 concept)
        template<typename Generator = std::mt19937_64>
        requires std::uniform_random_bit_generator<Generator>
        static BigNum random(size_t bits, Generator& gen = std::mt19937_64{std::random_device{}()}) {
            BigNum result;
            std::vector<uint8_t> bytes((bits + 7) / 8);
            std::generate(bytes.begin(), bytes.end(), gen);
            BN_bin2bn(bytes.data(), bytes.size(), result.bn);
            return result;
        }

        // Get internal BIGNUM (per compatibilità)
        [[nodiscard]] const BIGNUM* get() const { return bn; }
        [[nodiscard]] BIGNUM* get() { return bn; }
    };

    using CBigNum = BigNum; // Alias per compatibilità

    // ============================================================================
    // UINT256 (C++20 MODERN)
    // ============================================================================

    class uint256 {
    private:
        std::array<uint8_t, 32> data_{};

    public:
        constexpr uint256() = default;

        explicit uint256(std::span<const uint8_t> bytes) {
            if (bytes.size() != 32) {
                throw std::invalid_argument("uint256 requires exactly 32 bytes");
            }
            std::ranges::copy(bytes, data_.begin());
        }

        // Hash from string (C++20)
        static uint256 hash(std::string_view str) {
            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (!ctx) throw std::bad_alloc();

            uint256 result;
            if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
                EVP_DigestUpdate(ctx, str.data(), str.size()) != 1 ||
                EVP_DigestFinal_ex(ctx, result.data_.data(), nullptr) != 1) {
                EVP_MD_CTX_free(ctx);
            throw std::runtime_error("SHA256 failed");
                }

                EVP_MD_CTX_free(ctx);
                return result;
        }

        // Constexpr methods
        [[nodiscard]] constexpr bool isNull() const noexcept {
            return std::ranges::all_of(data_, [](uint8_t b) { return b == 0; });
        }

        [[nodiscard]] std::string toHex() const {
            constexpr auto hex_digits = "0123456789abcdef";
            std::string result(64, '0');

            for (size_t i = 0; i < 32; ++i) {
                result[2*i] = hex_digits[data_[i] >> 4];
                result[2*i + 1] = hex_digits[data_[i] & 0x0F];
            }
            return result;
        }

        [[nodiscard]] constexpr std::span<const uint8_t> bytes() const noexcept {
            return data_;
        }

        [[nodiscard]] constexpr bool operator==(const uint256& other) const noexcept {
            return data_ == other.data_;
        }

        [[nodiscard]] constexpr auto operator<=>(const uint256& other) const noexcept {
            return data_ <=> other.data_;
        }

        // Serialization support
        template<typename Archive>
        void serialize(Archive& ar) {
            ar(data_);
        }
    };

    // ============================================================================
    // ZEROCOIN PARAMS (C++20 MODERN)
    // ============================================================================

    class ZerocoinParams {
    private:
        CBigNum N_;  // RSA modulus
        CBigNum g_;  // Generator g ∈ QR(N)
        CBigNum h_;  // Generator h ∈ QR(N), h ≠ g
        uint32_t securityLevel_;
        uint32_t accumulatorParams_;

    public:
        ZerocoinParams(CBigNum N, CBigNum g, CBigNum h,
                       uint32_t securityLevel = ZEROCOIN_DEFAULT_SECURITYLEVEL,
                       uint32_t accumulatorParams = 2048)
        : N_(std::move(N)), g_(std::move(g)), h_(std::move(h)),
        securityLevel_(securityLevel), accumulatorParams_(accumulatorParams) {

            if (!validate()) {
                throw std::invalid_argument("Invalid Zerocoin parameters");
            }
        }

        // Factory method (C++20)
        [[nodiscard]] static std::unique_ptr<ZerocoinParams> generate(
            uint32_t securityLevel = ZEROCOIN_DEFAULT_SECURITYLEVEL,
            size_t rsaBits = 3072);

        // Validazione
        [[nodiscard]] bool validate() const;

        // Getters
        [[nodiscard]] const CBigNum& N() const& noexcept { return N_; }
        [[nodiscard]] const CBigNum& g() const& noexcept { return g_; }
        [[nodiscard]] const CBigNum& h() const& noexcept { return h_; }
        [[nodiscard]] uint32_t securityLevel() const noexcept { return securityLevel_; }
        [[nodiscard]] uint32_t accumulatorParams() const noexcept { return accumulatorParams_; }

        // Serialization
        template<typename Archive>
        void serialize(Archive& ar) {
            ar(N_, g_, h_, securityLevel_, accumulatorParams_);
        }
    };

    // ============================================================================
    // PUBLIC COIN (C++20)
    // ============================================================================

    class PublicCoin {
    private:
        std::shared_ptr<ZerocoinParams> params_;
        CBigNum value_;
        CoinDenomination denomination_;

    public:
        PublicCoin() : denomination_(CoinDenomination::ZQ_ERROR) {}

        PublicCoin(std::shared_ptr<ZerocoinParams> params,
                   CBigNum value,
                   CoinDenomination denomination)
        : params_(std::move(params)),
        value_(std::move(value)),
        denomination_(denomination) {

            if (!validate()) {
                throw std::invalid_argument("Invalid public coin");
            }
        }

        [[nodiscard]] bool validate() const;

        // Getters
        [[nodiscard]] const CBigNum& value() const& noexcept { return value_; }
        [[nodiscard]] CoinDenomination denomination() const noexcept { return denomination_; }
        [[nodiscard]] const auto& params() const& noexcept { return params_; }

        [[nodiscard]] bool operator==(const PublicCoin& other) const {
            return value_ == other.value_ && denomination_ == other.denomination_;
        }

        template<typename Archive>
        void serialize(Archive& ar) {
            ar(value_, denomination_);
        }
    };

    // ============================================================================
    // PRIVATE COIN (C++20)
    // ============================================================================

    class PrivateCoin {
    private:
        std::shared_ptr<ZerocoinParams> params_;
        CoinDenomination denomination_;
        CBigNum serialNumber_;
        CBigNum randomness_;
        PublicCoin publicCoin_;
        uint256 signature_;

    public:
        PrivateCoin(std::shared_ptr<ZerocoinParams> params,
                    CoinDenomination denomination);

        void mint();

        // Getters
        [[nodiscard]] const PublicCoin& publicCoin() const& noexcept { return publicCoin_; }
        [[nodiscard]] const CBigNum& serialNumber() const& noexcept { return serialNumber_; }
        [[nodiscard]] const CBigNum& randomness() const& noexcept { return randomness_; }
        [[nodiscard]] CoinDenomination denomination() const noexcept { return denomination_; }
        [[nodiscard]] const uint256& signature() const& noexcept { return signature_; }

        template<typename Archive>
        void serialize(Archive& ar) {
            ar(denomination_, serialNumber_, randomness_, publicCoin_, signature_);
        }

    private:
        void generateSerialNumber();
        void generateRandomness();
        [[nodiscard]] uint256 signCoin() const;
    };

    // ============================================================================
    // ACCUMULATOR (C++20 MODERN)
    // ============================================================================

    class Accumulator {
    private:
        std::shared_ptr<ZerocoinParams> params_;
        CBigNum value_;
        size_t coinCount_{0};
        CBigNum accumulatorModulus_;
        std::vector<CBigNum> accumulatedValues_;

    public:
        Accumulator(std::shared_ptr<ZerocoinParams> params,
                    CBigNum accumulatorModulus);

        // Modifica accumulator
        void accumulate(const CBigNum& coinValue);
        void remove(const CBigNum& coinValue);

        // Query
        [[nodiscard]] bool contains(const CBigNum& coinValue) const noexcept {
            return std::ranges::find(accumulatedValues_, coinValue) != accumulatedValues_.end();
        }

        // Getters
        [[nodiscard]] const CBigNum& value() const& noexcept { return value_; }
        [[nodiscard]] size_t coinCount() const noexcept { return coinCount_; }
        [[nodiscard]] const CBigNum& modulus() const& noexcept { return accumulatorModulus_; }

        // Calcola witness
        [[nodiscard]] CBigNum calculateWitness(const CBigNum& coinValue) const;

        template<typename Archive>
        void serialize(Archive& ar) {
            ar(value_, coinCount_, accumulatorModulus_, accumulatedValues_);
        }
    };

    // ============================================================================
    // COIN SPEND (C++20 COMPLETE)
    // ============================================================================

    class CoinSpend {
    public:
        enum class Version : uint8_t {
            V1 = ZEROCOIN_VERSION_1,
            V2 = ZEROCOIN_VERSION_2
        };

    private:
        Version version_;
        std::shared_ptr<ZerocoinParams> params_;
        CBigNum coinSerialNumber_;
        uint32_t accumulatorId_{0};
        CBigNum accumulatorValue_;
        uint256 ptxHash_;
        std::vector<uint8_t> accumulatorProof_;
        std::vector<uint8_t> serialNumberProof_;
        std::vector<uint8_t> signature_;

    public:
        CoinSpend() = default;

        CoinSpend(std::shared_ptr<ZerocoinParams> params,
                  const PrivateCoin& coin,
                  const Accumulator& accumulator,
                  uint32_t accumulatorId,
                  const uint256& ptxHash,
                  Version version = Version::V2);

        // Verifica
        [[nodiscard]] bool verify(const Accumulator& accumulator) const;
        [[nodiscard]] bool hasValidSignature() const;

        // Getters
        [[nodiscard]] Version version() const noexcept { return version_; }
        [[nodiscard]] const CBigNum& coinSerialNumber() const& noexcept { return coinSerialNumber_; }
        [[nodiscard]] uint32_t accumulatorId() const noexcept { return accumulatorId_; }
        [[nodiscard]] const CBigNum& accumulatorValue() const& noexcept { return accumulatorValue_; }
        [[nodiscard]] const uint256& txOutHash() const& noexcept { return ptxHash_; }

        template<typename Archive>
        void serialize(Archive& ar) {
            ar(version_, coinSerialNumber_, accumulatorId_,
               accumulatorValue_, ptxHash_, accumulatorProof_,
               serialNumberProof_, signature_);
        }

    private:
        void generateAccumulatorProof(const Accumulator& accumulator,
                                      const CBigNum& witness);
        void generateSerialNumberProof(const PrivateCoin& coin);
        [[nodiscard]] std::vector<uint8_t> getSignatureMessage() const;
    };

    // ============================================================================
    // UTILITY FUNCTIONS (C++20)
    // ============================================================================

    namespace utils {

        // Random generation
        [[nodiscard]] CBigNum randomBignum(const CBigNum& upperBound);
        [[nodiscard]] CBigNum randomPrime(size_t bits);

        // Modular arithmetic
        [[nodiscard]] CBigNum modExp(const CBigNum& base, const CBigNum& exp, const CBigNum& mod);
        [[nodiscard]] CBigNum modInverse(const CBigNum& a, const CBigNum& mod);
        [[nodiscard]] bool isQuadraticResidue(const CBigNum& a, const CBigNum& p);

        // Hash functions
        [[nodiscard]] std::vector<uint8_t> sha256(std::span<const uint8_t> data);
        [[nodiscard]] uint256 hashToUint256(std::span<const uint8_t> data);

        // Validazione
        [[nodiscard]] bool validateRSAModulus(const CBigNum& N);
        [[nodiscard]] bool validateGenerator(const CBigNum& g, const CBigNum& N);

        // C++20 concepts
        template<typename T>
        concept Hashable = requires(T t) {
            { std::hash<T>{}(t) } -> std::convertible_to<size_t>;
        };

    } // namespace utils

} // namespace libzerocoin
