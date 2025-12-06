#include "libzerocoin.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <vector>
#include <random>

namespace libzerocoin {

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

        // Generate random bytes using the provided generator
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

    // ===================== ZerocoinParams Implementation =====================
    ZerocoinParams::ZerocoinParams(CBigNum N, CBigNum g, CBigNum h,
                                   uint32_t securityLevel, uint32_t accumulatorSize)
    : N(std::move(N)), g(std::move(g)), h(std::move(h)),
    securityLevel(securityLevel), accumulatorSize(accumulatorSize) {}

    std::unique_ptr<ZerocoinParams> ZerocoinParams::generate(uint32_t securityLevel, size_t rsaBits) {
        CBigNum N = CBigNum::random(rsaBits);
        CBigNum g = CBigNum::random(256);
        CBigNum h = CBigNum::random(256);

        return std::make_unique<ZerocoinParams>(
            std::move(N),
                                                std::move(g),
                                                std::move(h),
                                                securityLevel,
                                                0  // accumulatorSize placeholder
        );
    }

    bool ZerocoinParams::validate() const {
        return !N.toHex().empty() &&
        !g.toHex().empty() &&
        !h.toHex().empty();
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
            params_->g.modExp(serialNumber_, params_->N),
                                 publicCoin_.denomination_
        );
    }

    // ===================== Accumulator Implementation =====================
    Accumulator::Accumulator(std::shared_ptr<ZerocoinParams> params, CBigNum value)
    : params_(std::move(params)), value_(std::move(value)), coinCount_(0) {}

    void Accumulator::accumulate(const CBigNum& coinValue) {
        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) throw std::bad_alloc();

        // Use accessor methods for private members
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

        // Use accessor methods for private members
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
    accumulatorValue_(accumulator.getValue()),  // Correct order
    ptxHash_(ptxHash),
    accumulatorId_(accumulatorId),
    version_(version) {}

    bool CoinSpend::verify(const Accumulator& accumulator) const {
        // Use accumulatorValue_ (not accumulatedValues_)
        if (accumulatorValue_.toHex() != accumulator.getValue().toHex()) {
            return false;
        }
        // ... other validations
        return true;
    }

    void CoinSpend::generateAccumulatorProof(const Accumulator& accumulator, const CBigNum& witness) {
        // Placeholder implementation
    }

    void CoinSpend::generateSerialNumberProof(const PrivateCoin& coin) {
        // Placeholder implementation
    }

} // namespace libzerocoin
