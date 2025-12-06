#include "libzerocoin.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <vector>
#include <random>

namespace libzerocoin {

    // Implement operator% for CBigNum
    CBigNum operator%(const CBigNum& a, const CBigNum& b) {
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) throw std::bad_alloc();

        CBigNum result;
        if (!BN_mod(result.get(), a.get(), b.get(), ctx)) {
            BN_CTX_free(ctx);
            throw std::runtime_error("BN_mod failed");
        }
        BN_CTX_free(ctx);
        return result;
    }

    // ===================== CBigNum Implementation =====================
    CBigNum::CBigNum() : bn(BN_new()) {
        if (!bn) throw std::bad_alloc();
    }

    CBigNum::CBigNum(const std::string& hex) : bn(BN_new()) {
        if (!bn) throw std::bad_alloc();
        if (!BN_hex2bn(&bn, hex.c_str())) {
            throw std::invalid_argument("Invalid hex string for CBigNum");
        }
    }

    CBigNum::CBigNum(const CBigNum& other) : bn(BN_dup(other.bn)) {
        if (!bn) throw std::bad_alloc();
    }

    CBigNum::~CBigNum() {
        if (bn) BN_free(bn);
    }

    CBigNum& CBigNum::operator=(const CBigNum& other) {
        if (this != &other) {
            BN_copy(bn, other.bn);
        }
        return *this;
    }

    CBigNum CBigNum::operator+(const CBigNum& other) const {
        CBigNum result;
        if (!BN_add(result.bn, bn, other.bn)) {
            throw std::runtime_error("BN_add failed");
        }
        return result;
    }

    CBigNum CBigNum::operator*(const CBigNum& other) const {
        CBigNum result;
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) throw std::bad_alloc();

        if (!BN_mul(result.bn, bn, other.bn, ctx)) {
            BN_CTX_free(ctx);
            throw std::runtime_error("BN_mul failed");
        }
        BN_CTX_free(ctx);
        return result;
    }

    CBigNum CBigNum::modExp(const CBigNum& exp, const CBigNum& mod) const {
        CBigNum result;
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) throw std::bad_alloc();

        if (!BN_mod_exp(result.bn, bn, exp.bn, mod.bn, ctx)) {
            BN_CTX_free(ctx);
            throw std::runtime_error("BN_mod_exp failed");
        }
        BN_CTX_free(ctx);
        return result;
    }

    CBigNum CBigNum::modInverse(const CBigNum& mod) const {
        CBigNum result;
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) throw std::bad_alloc();

        if (!BN_mod_inverse(result.bn, bn, mod.bn, ctx)) {
            BN_CTX_free(ctx);
            throw std::runtime_error("BN_mod_inverse failed");
        }
        BN_CTX_free(ctx);
        return result;
    }

    std::string CBigNum::toHex() const {
        char* hex = BN_bn2hex(bn);
        if (!hex) throw std::runtime_error("BN_bn2hex failed");
        std::string result(hex);
        OPENSSL_free(hex);
        return result;
    }

    CBigNum CBigNum::random(size_t bits, Generator gen) {
        CBigNum result;
        const size_t bytes = (bits + 7) / 8;
        std::vector<uint8_t> data(bytes);

        std::uniform_int_distribution<uint8_t> dist(0, 255);
        for (auto& byte : data) {
            byte = dist(gen);
        }

        if (!BN_bin2bn(data.data(), data.size(), result.bn)) {
            throw std::runtime_error("BN_bin2bn failed");
        }
        return result;
    }

    // ===================== uint256 Implementation =====================
    uint256::uint256(std::span<const uint8_t> bytes) {
        if (bytes.size() != 32) {
            throw std::invalid_argument("uint256 requires exactly 32 bytes");
        }
        std::copy(bytes.begin(), bytes.end(), data);
    }

    uint256::uint256(const std::string& hexStr) {
        if (hexStr.size() != 64) {
            throw std::invalid_argument("Invalid hex string length for uint256");
        }

        for (size_t i = 0; i < 32; ++i) {
            std::string byteStr = hexStr.substr(i * 2, 2);
            char* end = nullptr;
            unsigned long value = std::strtoul(byteStr.c_str(), &end, 16);

            if (end != byteStr.c_str() + 2 || value > 0xFF) {
                throw std::invalid_argument("Invalid hex digit in uint256 string");
            }
            data[i] = static_cast<uint8_t>(value);
        }
    }

    uint256 uint256::hash(std::string_view str) {
        uint256 result;
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, str.data(), str.size());
        SHA256_Final(result.data, &ctx);
        return result;
    }

    std::string uint256::toHex() const {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t b : data) {
            ss << std::setw(2) << static_cast<unsigned>(b);
        }
        return ss.str();
    }

    CBigNum uint256::toBigNum() const {
        CBigNum result;
        BN_bin2bn(data, sizeof(data), result.get());
        return result;
    }

    // ===================== uint512 Implementation =====================
    uint512::uint512(std::span<const uint8_t> bytes) {
        if (bytes.size() != 64) {
            throw std::invalid_argument("uint512 requires exactly 64 bytes");
        }
        std::copy(bytes.begin(), bytes.end(), data);
    }

    uint512::uint512(const std::string& hexStr) {
        if (hexStr.size() != 128) {
            throw std::invalid_argument("Invalid hex string length for uint512");
        }

        for (size_t i = 0; i < 64; ++i) {
            std::string byteStr = hexStr.substr(i * 2, 2);
            char* end = nullptr;
            unsigned long value = std::strtoul(byteStr.c_str(), &end, 16);

            if (end != byteStr.c_str() + 2 || value > 0xFF) {
                throw std::invalid_argument("Invalid hex digit in uint512 string");
            }
            data[i] = static_cast<uint8_t>(value);
        }
    }

    uint512 uint512::hash(std::string_view str) {
        uint512 result;
        SHA512_CTX ctx;
        SHA512_Init(&ctx);
        SHA512_Update(&ctx, str.data(), str.size());
        SHA512_Final(result.data, &ctx);
        return result;
    }

    std::string uint512::toHex() const {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t b : data) {
            ss << std::setw(2) << static_cast<unsigned>(b);
        }
        return ss.str();
    }

    CBigNum uint512::toBigNum() const {
        CBigNum result;
        BN_bin2bn(data, sizeof(data), result.get());
        return result;
    }

    // ===================== ZerocoinParams Implementation =====================
    ZerocoinParams::ZerocoinParams(CBigNum N, CBigNum g, CBigNum h, CBigNum H,
                                   uint32_t securityLevel, uint32_t accumulatorSize)
    : N(std::move(N)), g(std::move(g)), h(std::move(h)), H(std::move(H)),
    securityLevel(securityLevel), accumulatorSize(accumulatorSize) {}

    std::unique_ptr<ZerocoinParams> ZerocoinParams::generate(uint32_t securityLevel, size_t rsaBits) {
        CBigNum N = CBigNum::random(rsaBits);

        const auto g_str = "Generator g for Zerocoin, security: " + std::to_string(securityLevel);
        const auto h_str = "Generator h for Zerocoin, security: " + std::to_string(securityLevel);
        const auto H_str = "Generator H (SHA-512) for Zerocoin, security: " + std::to_string(securityLevel);

        CBigNum g = uint512::hash(g_str).toBigNum() % N;
        CBigNum h = uint512::hash(h_str).toBigNum() % N;
        CBigNum H = uint512::hash(H_str).toBigNum() % N;

        return std::make_unique<ZerocoinParams>(
            std::move(N),
                                                std::move(g),
                                                std::move(h),
                                                std::move(H),
                                                securityLevel,
                                                0
        );
    }

    bool ZerocoinParams::validate() const {
        return !N.toHex().empty() &&
        !g.toHex().empty() &&
        !h.toHex().empty() &&
        !H.toHex().empty();
    }

    // ===================== PublicCoin Implementation =====================
    PublicCoin::PublicCoin(std::shared_ptr<ZerocoinParams> params,
                           CBigNum value, CoinDenomination denom)
    : params_(std::move(params)), value_(std::move(value)), denomination_(denom) {}

    bool PublicCoin::validate() const {
        return params_ &&
        !value_.toHex().empty() &&
        denomination_ != ZQ_ERROR;
    }

    bool PublicCoin::operator==(const PublicCoin& other) const {
        return value_.toHex() == other.value_.toHex() &&
        denomination_ == other.denomination_;
    }

    // ===================== PrivateCoin Implementation =====================
    PrivateCoin::PrivateCoin(std::shared_ptr<ZerocoinParams> params, CoinDenomination denom)
    : params_(std::move(params)),
    publicCoin_(params_, CBigNum(), denom),
    serialNumber_(CBigNum::random(256)) {}

    void PrivateCoin::mint() {
        publicCoin_ = PublicCoin(
            params_,
            params_->H.modExp(serialNumber_, params_->N),
                                 publicCoin_.denomination_
        );
    }

    // ===================== Accumulator Implementation =====================
    Accumulator::Accumulator(std::shared_ptr<ZerocoinParams> params, CBigNum value)
    : params_(std::move(params)), value_(std::move(value)), coinCount_(0) {}

    void Accumulator::accumulate(const CBigNum& coinValue) {
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) throw std::bad_alloc();

        BN_mod_mul(
            value_.get(),
                   value_.get(),
                   coinValue.get(),
                   params_->N.get(),
                   ctx
        );
        BN_CTX_free(ctx);
        coinCount_++;
    }

    void Accumulator::remove(const CBigNum& coinValue) {
        CBigNum inv = coinValue.modInverse(params_->N);
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) throw std::bad_alloc();

        BN_mod_mul(
            value_.get(),
                   value_.get(),
                   inv.get(),
                   params_->N.get(),
                   ctx
        );
        BN_CTX_free(ctx);
        coinCount_--;
    }

    CBigNum Accumulator::getValue() const {
        return value_;
    }

    // ===================== CoinSpend Implementation =====================
    CoinSpend::CoinSpend(std::shared_ptr<ZerocoinParams> params,
                         const PrivateCoin& coin,
                         const Accumulator& accumulator,
                         uint32_t accumulatorId,
                         const uint256& ptxHash,
                         Version version)
    : params_(std::move(params)),
    coinSerialNumber_(coin.serialNumber_),
    accumulatorValue_(accumulator.getValue()),
    ptxHash_(ptxHash),
    accumulatorId_(accumulatorId),
    version_(version) {}

    bool CoinSpend::verify(const Accumulator& accumulator) const {
        if (accumulatorValue_.toHex() != accumulator.getValue().toHex()) {
            return false;
        }
        return true;
    }

    void CoinSpend::generateAccumulatorProof(const Accumulator& accumulator, const CBigNum& witness) {
        (void)accumulator;
        (void)witness;
    }

    void CoinSpend::generateSerialNumberProof(const PrivateCoin& coin) {
        (void)coin;
    }

} // namespace libzerocoin
