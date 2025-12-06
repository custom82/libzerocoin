// libzerocoin.hpp - HEADER COMPLETO C++20
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
#include <random>
#include <source_location>
#include <stdexcept>
#include <cstdint>
#include <algorithm>
#include <numeric>
#include <functional>
#include <iostream>

namespace libzerocoin {

    // ============================================================================
    // CONSTANTS & CONFIG
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

        explicit BigNum(const std::string& hex, int base) : bn(nullptr) {
            if (base == 16) {
                BN_hex2bn(&bn, hex.c_str());
            } else if (base == 10) {
                BN_dec2bn(&bn, hex.c_str());
            } else {
                throw std::runtime_error("Unsupported base");
            }
            if (!bn) throw std::runtime_error("Invalid number string");
        }

        explicit BigNum(uint64_t value) : bn(BN_new()) {
            if (!bn) throw std::bad_alloc();
            BN_set_word(bn, value);
        }

        // Costruttore da BIGNUM esistente
        explicit BigNum(BIGNUM* bignum) : bn(bignum) {
            if (!bn) throw std::bad_alloc();
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

        [[nodiscard]] std::string toDec() const {
            char* dec = BN_bn2dec(bn);
            if (!dec) throw std::runtime_error("BN_bn2dec failed");
            std::string result(dec);
            OPENSSL_free(dec);
            return result;
        }

        [[nodiscard]] std::vector<uint8_t> toBytes() const {
            std::vector<uint8_t> bytes(BN_num_bytes(bn));
            BN_bn2bin(bn, bytes.data());
            return bytes;
        }

        [[nodiscard]] size_t bitSize() const {
            return BN_num_bits(bn);
        }

        [[nodiscard]] size_t byteSize() const {
            return BN_num_bytes(bn);
        }

        // Operatori aritmetici
        BigNum operator+(const BigNum& other) const;
        BigNum operator-(const BigNum& other) const;
        BigNum operator*(const BigNum& other) const;
        BigNum operator/(const BigNum& other) const;
        BigNum operator%(const BigNum& other) const;

        BigNum& operator+=(const BigNum& other) {
            *this = *this + other;
            return *this;
        }

        BigNum& operator*=(const BigNum& other) {
            *this = *this * other;
            return *this;
        }

        // Modular arithmetic
        [[nodiscard]] BigNum modExp(const BigNum& exp, const BigNum& mod) const;
        [[nodiscard]] BigNum modInverse(const BigNum& mod) const;
        [[nodiscard]] BigNum mod(const BigNum& mod) const;

        // Bit operations
        void setBit(size_t bit) { BN_set_bit(bn, static_cast<int>(bit)); }
        void clearBit(size_t bit) { BN_clear_bit(bn, static_cast<int>(bit)); }
        [[nodiscard]] bool testBit(size_t bit) const { return BN_is_bit_set(bn, static_cast<int>(bit)); }

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

        [[nodiscard]] bool operator<=(const BigNum& other) const {
            return BN_cmp(bn, other.bn) <= 0;
        }

        [[nodiscard]] bool operator>(const BigNum& other) const {
            return BN_cmp(bn, other.bn) > 0;
        }

        [[nodiscard]] bool operator>=(const BigNum& other) const {
            return BN_cmp(bn, other.bn) >= 0;
        }

        // Utility
        [[nodiscard]] bool isZero() const { return BN_is_zero(bn); }
        [[nodiscard]] bool isOne() const { return BN_is_one(bn); }
        [[nodiscard]] bool isOdd() const { return BN_is_odd(bn); }
        [[nodiscard]] bool isEven() const { return !isOdd(); }
        [[nodiscard]] bool isNegative() const { return BN_is_negative(bn); }

        void negate() { BN_set_negative(bn, !BN_is_negative(bn)); }
        [[nodiscard]] BigNum abs() const {
            BigNum result = *this;
            BN_set_negative(result.bn, 0);
            return result;
        }

        // Random generation (C++20 concept)
        template<typename Generator = std::mt19937_64>
        requires std::uniform_random_bit_generator<Generator>
        static BigNum random(size_t bits, Generator& gen = std::mt19937_64{std::random_device{}()});

        static BigNum randomPrime(size_t bits) {
            BigNum result;
            if (!BN_generate_prime_ex(result.bn, static_cast<int>(bits), 1, nullptr, nullptr, nullptr)) {
                throw std::runtime_error("Failed to generate prime");
            }
            return result;
        }

        static BigNum fromBytes(const std::vector<uint8_t>& bytes) {
            BigNum result;
            BN_bin2bn(bytes.data(), static_cast<int>(bytes.size()), result.bn);
            return result;
        }

        // Get internal BIGNUM
        [[nodiscard]] const BIGNUM* get() const { return bn; }
        [[nodiscard]] BIGNUM* get() { return bn; }

        // Serialization support
        template<typename Archive>
        void serialize(Archive& ar) {
            std::string hex = toHex();
            ar & hex;
            if constexpr (Archive::is_loading::value) {
                *this = BigNum(hex, 16);
            }
        }
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

        explicit uint256(const std::string& hexStr);
        explicit uint256(std::span<const uint8_t> bytes);

        // Static factory methods
        static uint256 zero() { return uint256(); }
        static uint256 one();
        static uint256 max();

        // Hash from string/data
        static uint256 hash(std::string_view str);
        static uint256 hash(std::span<const uint8_t> data);

        // Constexpr methods
        [[nodiscard]] constexpr bool isNull() const noexcept {
            return std::ranges::all_of(data_, [](uint8_t b) { return b == 0; });
        }

        [[nodiscard]] constexpr bool isOne() const noexcept {
            return data_[0] == 1 && std::ranges::all_of(
                std::span(data_.begin() + 1, data_.end()),
                                                        [](uint8_t b) { return b == 0; }
            );
        }

        // Conversion
        [[nodiscard]] std::string toHex() const;
        [[nodiscard]] std::string toString() const { return toHex(); }
        [[nodiscard]] std::string GetHex() const { return toHex(); }

        [[nodiscard]] constexpr std::span<const uint8_t> bytes() const noexcept {
            return data_;
        }

        [[nodiscard]] constexpr std::span<uint8_t> bytes() noexcept {
            return data_;
        }

        [[nodiscard]] constexpr const std::array<uint8_t, 32>& GetData() const noexcept {
            return data_;
        }

        // Comparators
        [[nodiscard]] constexpr bool operator==(const uint256& other) const noexcept {
            return data_ == other.data_;
        }

        [[nodiscard]] constexpr bool operator!=(const uint256& other) const noexcept {
            return !(*this == other);
        }

        [[nodiscard]] constexpr auto operator<=>(const uint256& other) const noexcept {
            for (size_t i = 0; i < 32; ++i) {
                if (data_[i] != other.data_[i]) {
                    return data_[i] <=> other.data_[i];
                }
            }
            return std::strong_ordering::equal;
        }

        // Bit operations
        [[nodiscard]] uint256 operator&(const uint256& other) const;
        [[nodiscard]] uint256 operator|(const uint256& other) const;
        [[nodiscard]] uint256 operator^(const uint256& other) const;
        [[nodiscard]] uint256 operator~() const;

        uint256& operator&=(const uint256& other);
        uint256& operator|=(const uint256& other);
        uint256& operator^=(const uint256& other);

        // Shift operations
        [[nodiscard]] uint256 operator<<(size_t shift) const;
        [[nodiscard]] uint256 operator>>(size_t shift) const;

        uint256& operator<<=(size_t shift);
        uint256& operator>>=(size_t shift);

        // Arithmetic (modulo 2^256)
        [[nodiscard]] uint256 operator+(const uint256& other) const;
        [[nodiscard]] uint256 operator-(const uint256& other) const;
        [[nodiscard]] uint256 operator*(const uint256& other) const;
        [[nodiscard]] uint256 operator/(const uint256& other) const;
        [[nodiscard]] uint256 operator%(const uint256& other) const;

        uint256& operator+=(const uint256& other);
        uint256& operator-=(const uint256& other);
        uint256& operator*=(const uint256& other);
        uint256& operator/=(const uint256& other);
        uint256& operator%=(const uint256& other);

        // Increment/Decrement
        uint256& operator++();    // prefix
        uint256 operator++(int);  // postfix
        uint256& operator--();    // prefix
        uint256 operator--(int);  // postfix

        // Serialization
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
        CBigNum N_;  // RSA modulus (product of two safe primes)
        CBigNum g_;  // Generator g ∈ QR(N)
        CBigNum h_;  // Generator h ∈ QR(N), h ≠ g
        uint32_t securityLevel_;
        uint32_t accumulatorParams_;

    public:
        ZerocoinParams() = default;

        ZerocoinParams(CBigNum N, CBigNum g, CBigNum h,
                       uint32_t securityLevel = ZEROCOIN_DEFAULT_SECURITYLEVEL,
                       uint32_t accumulatorParams = 2048);

        // Factory method (C++20)
        [[nodiscard]] static std::unique_ptr<ZerocoinParams> generate(
            uint32_t securityLevel = ZEROCOIN_DEFAULT_SECURITYLEVEL,
            size_t rsaBits = 3072);

        // Validazione completa dei parametri
        [[nodiscard]] bool validate() const;

        // Getters
        [[nodiscard]] const CBigNum& N() const& noexcept { return N_; }
        [[nodiscard]] CBigNum N() && noexcept { return std::move(N_); }

        [[nodiscard]] const CBigNum& g() const& noexcept { return g_; }
        [[nodiscard]] CBigNum g() && noexcept { return std::move(g_); }

        [[nodiscard]] const CBigNum& h() const& noexcept { return h_; }
        [[nodiscard]] CBigNum h() && noexcept { return std::move(h_); }

        [[nodiscard]] uint32_t securityLevel() const noexcept { return securityLevel_; }
        [[nodiscard]] uint32_t accumulatorParams() const noexcept { return accumulatorParams_; }

        // Utility
        [[nodiscard]] CBigNum getAccumulatorBase() const { return g_; }
        [[nodiscard]] size_t getModulusSize() const { return N_.bitSize(); }

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
                   CoinDenomination denomination);

        // Validazione
        [[nodiscard]] bool validate() const;

        // Getters
        [[nodiscard]] const CBigNum& value() const& noexcept { return value_; }
        [[nodiscard]] CBigNum value() && noexcept { return std::move(value_); }

        [[nodiscard]] CoinDenomination denomination() const noexcept { return denomination_; }
        [[nodiscard]] const std::shared_ptr<ZerocoinParams>& params() const& noexcept { return params_; }

        // Comparators
        [[nodiscard]] bool operator==(const PublicCoin& other) const;
        [[nodiscard]] bool operator!=(const PublicCoin& other) const { return !(*this == other); }

        // Utility
        [[nodiscard]] std::string toString() const {
            return std::format("PublicCoin(denom={}, value={}...)",
                               static_cast<uint64_t>(denomination_),
                               value_.toHex().substr(0, 16));
        }

        // Serialization
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

        // Generazione moneta
        void mint();

        // Getters
        [[nodiscard]] const PublicCoin& publicCoin() const& noexcept { return publicCoin_; }
        [[nodiscard]] PublicCoin publicCoin() && noexcept { return std::move(publicCoin_); }

        [[nodiscard]] const CBigNum& serialNumber() const& noexcept { return serialNumber_; }
        [[nodiscard]] CBigNum serialNumber() && noexcept { return std::move(serialNumber_); }

        [[nodiscard]] const CBigNum& randomness() const& noexcept { return randomness_; }
        [[nodiscard]] CBigNum randomness() && noexcept { return std::move(randomness_); }

        [[nodiscard]] CoinDenomination denomination() const noexcept { return denomination_; }
        [[nodiscard]] const uint256& signature() const& noexcept { return signature_; }
        [[nodiscard]] const std::shared_ptr<ZerocoinParams>& params() const& noexcept { return params_; }

        // Utility
        [[nodiscard]] std::string toString() const {
            return std::format("PrivateCoin(denom={}, serial={}...)",
                               static_cast<uint64_t>(denomination_),
                               serialNumber_.toHex().substr(0, 16));
        }

        // Serialization
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
        [[nodiscard]] CBigNum value() && noexcept { return std::move(value_); }

        [[nodiscard]] size_t coinCount() const noexcept { return coinCount_; }
        [[nodiscard]] const CBigNum& modulus() const& noexcept { return accumulatorModulus_; }
        [[nodiscard]] const std::vector<CBigNum>& accumulatedValues() const& noexcept { return accumulatedValues_; }

        // Calcola witness per prova di inclusione
        [[nodiscard]] CBigNum calculateWitness(const CBigNum& coinValue) const;

        // Utility
        [[nodiscard]] std::string toString() const {
            return std::format("Accumulator(coins={}, value={}...)",
                               coinCount_,
                               value_.toHex().substr(0, 16));
        }

        // Serialization
        template<typename Archive>
        void serialize(Archive& ar) {
            ar(value_, coinCount_, accumulatorModulus_, accumulatedValues_);
        }
    };

    // ============================================================================
    // ACCUMULATOR WITNESS (C++20)
    // ============================================================================

    class AccumulatorWitness {
    private:
        std::shared_ptr<ZerocoinParams> params_;
        CBigNum value_;
        CBigNum element_;
        std::shared_ptr<Accumulator> accumulator_;

    public:
        AccumulatorWitness(std::shared_ptr<ZerocoinParams> params,
                           std::shared_ptr<Accumulator> accumulator,
                           const CBigNum& element);

        // Aggiorna witness quando si aggiungono nuove monete
        void addElement(const CBigNum& elementValue);

        // Verifica witness
        [[nodiscard]] bool verifyWitness(const Accumulator& acc, const CBigNum& elementValue) const;

        // Getters
        [[nodiscard]] const CBigNum& value() const& noexcept { return value_; }
        [[nodiscard]] const CBigNum& element() const& noexcept { return element_; }
        [[nodiscard]] const std::shared_ptr<Accumulator>& accumulator() const& noexcept { return accumulator_; }

        // Serialization
        template<typename Archive>
        void serialize(Archive& ar) {
            ar(value_, element_);
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

        // Verifica completa
        [[nodiscard]] bool verify(const Accumulator& accumulator) const;
        [[nodiscard]] bool hasValidSignature() const;

        // Getters
        [[nodiscard]] Version version() const noexcept { return version_; }

        [[nodiscard]] const CBigNum& coinSerialNumber() const& noexcept { return coinSerialNumber_; }
        [[nodiscard]] CBigNum coinSerialNumber() && noexcept { return std::move(coinSerialNumber_); }

        [[nodiscard]] uint32_t accumulatorId() const noexcept { return accumulatorId_; }

        [[nodiscard]] const CBigNum& accumulatorValue() const& noexcept { return accumulatorValue_; }
        [[nodiscard]] CBigNum accumulatorValue() && noexcept { return std::move(accumulatorValue_); }

        [[nodiscard]] const uint256& txOutHash() const& noexcept { return ptxHash_; }
        [[nodiscard]] uint256 txOutHash() && noexcept { return std::move(ptxHash_); }

        [[nodiscard]] const std::vector<uint8_t>& accumulatorProof() const& noexcept { return accumulatorProof_; }
        [[nodiscard]] const std::vector<uint8_t>& serialNumberProof() const& noexcept { return serialNumberProof_; }
        [[nodiscard]] const std::vector<uint8_t>& signature() const& noexcept { return signature_; }

        // Utility
        [[nodiscard]] std::string toString() const {
            return std::format("CoinSpend(v{}, serial={}..., accId={})",
                               static_cast<uint8_t>(version_),
                               coinSerialNumber_.toHex().substr(0, 16),
                               accumulatorId_);
        }

        // Serialization
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
    // COMMITMENT (C++20 - Per commitment scheme)
    // ============================================================================

    class Commitment {
    private:
        std::shared_ptr<ZerocoinParams> params_;
        CBigNum value_;
        CBigNum randomness_;
        CBigNum commitment_;

    public:
        Commitment(std::shared_ptr<ZerocoinParams> params,
                   const CBigNum& value,
                   const CBigNum& randomness);

        // Getters
        [[nodiscard]] const CBigNum& value() const& noexcept { return value_; }
        [[nodiscard]] const CBigNum& randomness() const& noexcept { return randomness_; }
        [[nodiscard]] const CBigNum& commitment() const& noexcept { return commitment_; }

        // Verifica
        [[nodiscard]] bool verify() const;

        // Serialization
        template<typename Archive>
        void serialize(Archive& ar) {
            ar(value_, randomness_, commitment_);
        }
    };

    // ============================================================================
    // UTILITY FUNCTIONS (C++20)
    // ============================================================================

    namespace utils {

        // Random generation
        [[nodiscard]] CBigNum randomBignum(const CBigNum& upperBound);
        [[nodiscard]] CBigNum randomBignum(size_t bits);
        [[nodiscard]] CBigNum randomPrime(size_t bits);
        [[nodiscard]] CBigNum randomSafePrime(size_t bits);

        // Modular arithmetic
        [[nodiscard]] CBigNum modExp(const CBigNum& base, const CBigNum& exp, const CBigNum& mod);
        [[nodiscard]] CBigNum modInverse(const CBigNum& a, const CBigNum& mod);
        [[nodiscard]] bool isQuadraticResidue(const CBigNum& a, const CBigNum& p);

        // Hash functions
        [[nodiscard]] std::vector<uint8_t> sha256(std::span<const uint8_t> data);
        [[nodiscard]] std::vector<uint8_t> sha256(const std::string& str);
        [[nodiscard]] std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);

        [[nodiscard]] uint256 hashToUint256(std::span<const uint8_t> data);
        [[nodiscard]] uint256 hashToUint256(const std::string& str);

        // Validazione parametri
        [[nodiscard]] bool validateRSAModulus(const CBigNum& N);
        [[nodiscard]] bool validateGenerator(const CBigNum& g, const CBigNum& N);
        [[nodiscard]] bool validateCoinCommitment(const CBigNum& commitment, const CBigNum& N);

        // Conversioni
        [[nodiscard]] std::string bytesToHex(std::span<const uint8_t> bytes);
        [[nodiscard]] std::vector<uint8_t> hexToBytes(const std::string& hex);

        // Padding e formattazione
        [[nodiscard]] std::vector<uint8_t> padToSize(std::span<const uint8_t> data, size_t size);
        [[nodiscard]] std::vector<uint8_t> removePadding(std::span<const uint8_t> data);

        // C++20 concepts
        template<typename T>
        concept Hashable = requires(T t) {
            { std::hash<T>{}(t) } -> std::convertible_to<size_t>;
        };

        template<typename T>
        concept Serializable = requires(T t, std::ostream& os, std::istream& is) {
            { os << t } -> std::same_as<std::ostream&>;
            { is >> t } -> std::same_as<std::istream&>;
        };

    } // namespace utils

    // ============================================================================
    // SERIAL NUMBER SIGNATURE OF KNOWLEDGE (C++20)
    // ============================================================================

    class SerialNumberSignatureOfKnowledge {
    private:
        std::vector<uint8_t> signature_;
        CBigNum challenge_;
        std::vector<CBigNum> responses_;

    public:
        SerialNumberSignatureOfKnowledge() = default;

        // Genera signature
        void generate(const std::shared_ptr<ZerocoinParams>& params,
                      const CBigNum& serialNumber,
                      const CBigNum& randomness,
                      const CBigNum& coinCommitment);

        // Verifica signature
        [[nodiscard]] bool verify(const std::shared_ptr<ZerocoinParams>& params,
                                  const CBigNum& serialNumber,
                                  const CBigNum& coinCommitment) const;

                                  // Getters
                                  [[nodiscard]] const std::vector<uint8_t>& signature() const& noexcept { return signature_; }
                                  [[nodiscard]] const CBigNum& challenge() const& noexcept { return challenge_; }
                                  [[nodiscard]] const std::vector<CBigNum>& responses() const& noexcept { return responses_; }

                                  // Serialization
                                  template<typename Archive>
                                  void serialize(Archive& ar) {
                                      ar(signature_, challenge_, responses_);
                                  }
    };

    // ============================================================================
    // ACCUMULATOR PROOF OF KNOWLEDGE (C++20)
    // ============================================================================

    class AccumulatorProofOfKnowledge {
    private:
        std::vector<uint8_t> proof_;
        CBigNum challenge_;
        std::vector<CBigNum> responses_;

    public:
        AccumulatorProofOfKnowledge() = default;

        // Genera proof
        void generate(const std::shared_ptr<ZerocoinParams>& params,
                      const CBigNum& accumulatorValue,
                      const CBigNum& coinCommitment,
                      const CBigNum& witness);

        // Verifica proof
        [[nodiscard]] bool verify(const std::shared_ptr<ZerocoinParams>& params,
                                  const CBigNum& accumulatorValue,
                                  const CBigNum& coinCommitment) const;

                                  // Getters
                                  [[nodiscard]] const std::vector<uint8_t>& proof() const& noexcept { return proof_; }
                                  [[nodiscard]] const CBigNum& challenge() const& noexcept { return challenge_; }
                                  [[nodiscard]] const std::vector<CBigNum>& responses() const& noexcept { return responses_; }

                                  // Serialization
                                  template<typename Archive>
                                  void serialize(Archive& ar) {
                                      ar(proof_, challenge_, responses_);
                                  }
    };

    // ============================================================================
    // ZEROCOIN EXCEPTIONS (C++20)
    // ============================================================================

    class ZerocoinException : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;

        ZerocoinException(const std::string& msg,
                          std::source_location loc = std::source_location::current())
        : std::runtime_error(std::format("{} at {}:{}",
                                         msg,
                                         loc.file_name(),
                                         loc.line())) {}
    };

    class InvalidParamsException : public ZerocoinException {
    public:
        InvalidParamsException(const std::string& msg,
                               std::source_location loc = std::source_location::current())
        : ZerocoinException("Invalid params: " + msg, loc) {}
    };

    class InvalidCoinException : public ZerocoinException {
    public:
        InvalidCoinException(const std::string& msg,
                             std::source_location loc = std::source_location::current())
        : ZerocoinException("Invalid coin: " + msg, loc) {}
    };

    class AccumulatorException : public ZerocoinException {
    public:
        AccumulatorException(const std::string& msg,
                             std::source_location loc = std::source_location::current())
        : ZerocoinException("Accumulator error: " + msg, loc) {}
    };

    class VerificationException : public ZerocoinException {
    public:
        VerificationException(const std::string& msg,
                              std::source_location loc = std::source_location::current())
        : ZerocoinException("Verification failed: " + msg, loc) {}
    };

} // namespace libzerocoin
