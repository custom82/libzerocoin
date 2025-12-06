#pragma once

#include <memory>
#include <string>
#include <vector>
#include <span>
#include <cstdint>
#include <random>
#include <stdexcept>
#include <openssl/bn.h>
#include <openssl/sha.h>

namespace libzerocoin {

    class CBigNum {
    private:
        BIGNUM* bn;
    public:
        CBigNum();
        explicit CBigNum(const std::string& hex);
        CBigNum(const CBigNum& other);
        ~CBigNum();

        // Access methods for OpenSSL operations
        BIGNUM* get() const { return bn; }
        BIGNUM** get_ptr() { return &bn; }

        CBigNum& operator=(const CBigNum& other);
        CBigNum operator+(const CBigNum& other) const;
        CBigNum operator*(const CBigNum& other) const;
        CBigNum modExp(const CBigNum& exp, const CBigNum& mod) const;
        [[nodiscard]] CBigNum modInverse(const CBigNum& mod) const;
        [[nodiscard]] std::string toHex() const;

        // Use standard generator type
        using Generator = std::mt19937_64;

        // Fixed: Accept generator by value
        static CBigNum random(size_t bits, Generator gen = Generator{std::random_device{}()});
    };

    class uint256 {
    private:
        uint8_t data[32];
    public:
        constexpr uint256() : data{0} {}
        explicit uint256(std::span<const uint8_t> bytes);
        explicit uint256(const std::string& hexStr);

        static uint256 hash(std::string_view str);
        [[nodiscard]] std::string toHex() const;
    };

    enum CoinDenomination {
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

    class ZerocoinParams {
    public:
        ZerocoinParams(CBigNum N, CBigNum g, CBigNum h, uint32_t securityLevel, uint32_t accumulatorSize);
        static std::unique_ptr<ZerocoinParams> generate(uint32_t securityLevel, size_t rsaBits = 2048);
        [[nodiscard]] bool validate() const;

        CBigNum N;
        CBigNum g;
        CBigNum h;
        uint32_t securityLevel;
        uint32_t accumulatorSize;
    };

    class PublicCoin {
    public:
        PublicCoin(std::shared_ptr<ZerocoinParams> params, CBigNum value, CoinDenomination denom);
        [[nodiscard]] bool validate() const;
        [[nodiscard]] bool operator==(const PublicCoin& other) const;

        std::shared_ptr<ZerocoinParams> params_;
        CBigNum value_;
        CoinDenomination denomination_;
    };

    class PrivateCoin {
    public:
        explicit PrivateCoin(std::shared_ptr<ZerocoinParams> params, CoinDenomination denom);
        void mint();

        std::shared_ptr<ZerocoinParams> params_;
        PublicCoin publicCoin_;
        CBigNum serialNumber_;
    };

    class Accumulator {
    public:
        Accumulator(std::shared_ptr<ZerocoinParams> params, CBigNum value);
        void accumulate(const CBigNum& coinValue);
        void remove(const CBigNum& coinValue);
        [[nodiscard]] CBigNum getValue() const;

        std::shared_ptr<ZerocoinParams> params_;
        CBigNum value_;
        uint32_t coinCount_;
    };

    enum Version { V1, V2 };

    class CoinSpend {
    public:
        CoinSpend(std::shared_ptr<ZerocoinParams> params,
                  const PrivateCoin& coin,
                  const Accumulator& accumulator,
                  uint32_t accumulatorId,
                  const uint256& ptxHash,
                  Version version = V2);
        [[nodiscard]] bool verify(const Accumulator& accumulator) const;
        void generateAccumulatorProof(const Accumulator& accumulator, const CBigNum& witness);
        void generateSerialNumberProof(const PrivateCoin& coin);

        // Correct order (matches initialization)
        std::shared_ptr<ZerocoinParams> params_;
        CBigNum coinSerialNumber_;
        CBigNum accumulatorValue_;
        uint256 ptxHash_;
        uint32_t accumulatorId_;
        Version version_;
    };

} // namespace libzerocoin
