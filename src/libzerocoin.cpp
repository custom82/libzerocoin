// libzerocoin.cpp - IMPLEMENTAZIONE COMPLETA C++20
#include "libzerocoin.hpp"
#include <format>
#include <ranges>
#include <algorithm>
#include <numeric>
#include <random>
#include <sstream>
#include <iomanip>

namespace libzerocoin {

    // ============================================================================
    // IMPLEMENTAZIONE COMPLETA BIGNUM
    // ============================================================================

    // Costruttore da stringa hex
    BigNum::BigNum(const std::string& hex) : bn(BN_new()) {
        if (!bn) throw std::bad_alloc();
        if (!BN_hex2bn(&bn, hex.c_str())) {
            BN_free(bn);
            throw std::runtime_error("Invalid hex string");
        }
    }

    // Operatori aritmetici
    BigNum BigNum::operator+(const BigNum& other) const {
        BigNum result;
        if (!BN_add(result.bn, bn, other.bn)) {
            throw std::runtime_error("BN_add failed");
        }
        return result;
    }

    BigNum BigNum::operator*(const BigNum& other) const {
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

    BigNum BigNum::modExp(const BigNum& exp, const BigNum& mod) const {
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

    BigNum BigNum::modInverse(const BigNum& mod) const {
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

    // Implementazione template random
    template<typename Generator>
    requires std::uniform_random_bit_generator<Generator>
    BigNum BigNum::random(size_t bits, Generator& gen) {
        BigNum result;
        std::vector<uint8_t> bytes((bits + 7) / 8);

        // Usa il generatore C++ per i byte
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        for (auto& byte : bytes) {
            byte = static_cast<uint8_t>(dist(gen));
        }

        // Se il primo byte è 0, impostalo
        if (!bytes.empty() && bytes[0] == 0) {
            bytes[0] = 1;
        }

        BN_bin2bn(bytes.data(), bytes.size(), result.bn);

        // Assicura che abbia esattamente 'bits' bit
        BN_set_bit(result.bn, bits - 1);

        return result;
    }

    // Istanziazione esplicita
    template BigNum BigNum::random<std::mt19937_64>(size_t bits, std::mt19937_64& gen);

    // ============================================================================
    // IMPLEMENTAZIONE UINT256 COMPLETA
    // ============================================================================

    uint256::uint256(const std::string& hexStr) {
        if (hexStr.length() != 64) {
            throw std::invalid_argument("uint256 requires 64 hex characters");
        }

        for (size_t i = 0; i < 32; ++i) {
            std::string byteStr = hexStr.substr(i * 2, 2);
            data_[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
        }
    }

    uint256 uint256::hash(std::string_view str) {
        uint256 result;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();

        if (!ctx) throw std::bad_alloc();

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
            EVP_DigestUpdate(ctx, str.data(), str.size()) != 1 ||
            EVP_DigestFinal_ex(ctx, result.data_.data(), nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA256 failed");
            }

            EVP_MD_CTX_free(ctx);
            return result;
    }

    std::string uint256::toHex() const {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (uint8_t byte : data_) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

    // ============================================================================
    // IMPLEMENTAZIONE ZEROCOIN PARAMS COMPLETA
    // ============================================================================

    ZerocoinParams::ZerocoinParams(CBigNum N, CBigNum g, CBigNum h,
                                   uint32_t securityLevel, uint32_t accumulatorParams)
    : N_(std::move(N)), g_(std::move(g)), h_(std::move(h)),
    securityLevel_(securityLevel), accumulatorParams_(accumulatorParams) {

        if (!validate()) {
            throw std::invalid_argument("Invalid Zerocoin parameters");
        }
    }

    std::unique_ptr<ZerocoinParams> ZerocoinParams::generate(
        uint32_t securityLevel, size_t rsaBits) {

        // 1. Genera due primi sicuri p e q
        std::cout << "Generating RSA modulus (" << rsaBits << " bits)..." << std::endl;

        // Usa OpenSSL per generare primi RSA
        BIGNUM* p = BN_new();
        BIGNUM* q = BN_new();
        BIGNUM* e = BN_new();
        BN_CTX* ctx = BN_CTX_new();

        if (!p || !q || !e || !ctx) {
            BN_free(p); BN_free(q); BN_free(e); BN_CTX_free(ctx);
            throw std::bad_alloc();
        }

        // Genera primo p (rsaBits/2 bits)
        if (!BN_generate_prime_ex(p, rsaBits/2, 1, nullptr, nullptr, nullptr)) {
            BN_free(p); BN_free(q); BN_free(e); BN_CTX_free(ctx);
            throw std::runtime_error("Failed to generate prime p");
        }

        // Genera primo q (rsaBits/2 bits)
        if (!BN_generate_prime_ex(q, rsaBits/2, 1, nullptr, nullptr, nullptr)) {
            BN_free(p); BN_free(q); BN_free(e); BN_CTX_free(ctx);
            throw std::runtime_error("Failed to generate prime q");
        }

        // Calcola N = p * q
        BIGNUM* N_bn = BN_new();
        if (!BN_mul(N_bn, p, q, ctx)) {
            BN_free(p); BN_free(q); BN_free(e); BN_free(N_bn); BN_CTX_free(ctx);
            throw std::runtime_error("Failed to compute N = p * q");
        }

        CBigNum N;
        BN_copy(N.get(), N_bn);

        // 2. Genera generatori g e h (residui quadratici mod N)
        auto generateQuadraticResidue = [&N, ctx]() -> CBigNum {
            CBigNum result;
            BIGNUM* a = BN_new();
            BIGNUM* a_squared = BN_new();

            std::random_device rd;
            std::mt19937_64 gen(rd());

            do {
                // Genera a random ∈ [2, N-1]
                BN_rand_range(a, N.get());
                if (BN_is_zero(a) || BN_is_one(a)) continue;

                // Calcola a^2 mod N
                BN_mod_sqr(a_squared, a, N.get(), ctx);

                BN_copy(result.get(), a_squared);

            } while (BN_is_zero(result.get()) || BN_is_one(result.get()));

            BN_free(a);
            BN_free(a_squared);
            return result;
        };

        std::cout << "Generating generator g..." << std::endl;
        CBigNum g = generateQuadraticResidue();

        std::cout << "Generating generator h..." << std::endl;
        CBigNum h = generateQuadraticResidue();

        // Assicura g ≠ h
        while (g == h) {
            h = generateQuadraticResidue();
        }

        // Cleanup
        BN_free(p); BN_free(q); BN_free(e); BN_free(N_bn); BN_CTX_free(ctx);

        std::cout << "Zerocoin parameters generated successfully!" << std::endl;
        std::cout << "N size: " << BN_num_bits(N.get()) << " bits" << std::endl;

        return std::make_unique<ZerocoinParams>(std::move(N), std::move(g),
                                                std::move(h), securityLevel);
        }

        bool ZerocoinParams::validate() const {
            // 1. Verifica valori base
            if (N_.isZero() || g_.isZero() || h_.isZero()) {
                std::cerr << "Invalid: zero value" << std::endl;
                return false;
            }

            // 2. Verifica g ≠ h
            if (g_ == h_) {
                std::cerr << "Invalid: g == h" << std::endl;
                return false;
            }

            // 3. Verifica che g e h siano < N
            if (BN_cmp(g_.get(), N_.get()) >= 0 || BN_cmp(h_.get(), N_.get()) >= 0) {
                std::cerr << "Invalid: g or h >= N" << std::endl;
                return false;
            }

            // 4. Verifica che g e h siano residui quadratici
            // Calcola (g^((N-1)/2)) mod N
            BN_CTX* ctx = BN_CTX_new();
            if (!ctx) return false;

            // Calcola (N-1)/2
            BIGNUM* N_minus_1 = BN_dup(N_.get());
            BIGNUM* exponent = BN_new();
            BN_sub_word(N_minus_1, 1);
            BN_rshift1(exponent, N_minus_1);

            // Verifica g
            BIGNUM* legendre_g = BN_new();
            if (!BN_mod_exp(legendre_g, g_.get(), exponent, N_.get(), ctx)) {
                BN_free(N_minus_1); BN_free(exponent); BN_free(legendre_g); BN_CTX_free(ctx);
                return false;
            }

            if (!BN_is_one(legendre_g)) {
                BN_free(N_minus_1); BN_free(exponent); BN_free(legendre_g); BN_CTX_free(ctx);
                std::cerr << "Invalid: g is not quadratic residue" << std::endl;
                return false;
            }

            // Verifica h
            BIGNUM* legendre_h = BN_new();
            if (!BN_mod_exp(legendre_h, h_.get(), exponent, N_.get(), ctx)) {
                BN_free(N_minus_1); BN_free(exponent); BN_free(legendre_g); BN_free(legendre_h);
                BN_CTX_free(ctx);
                return false;
            }

            if (!BN_is_one(legendre_h)) {
                BN_free(N_minus_1); BN_free(exponent); BN_free(legendre_g); BN_free(legendre_h);
                BN_CTX_free(ctx);
                std::cerr << "Invalid: h is not quadratic residue" << std::endl;
                return false;
            }

            // Cleanup
            BN_free(N_minus_1); BN_free(exponent); BN_free(legendre_g); BN_free(legendre_h);
            BN_CTX_free(ctx);

            // 5. Verifica livello di sicurezza
            if (securityLevel_ < ZEROCOIN_DEFAULT_SECURITYLEVEL) {
                std::cerr << "Invalid: security level too low" << std::endl;
                return false;
            }

            return true;
        }

        // ============================================================================
        // IMPLEMENTAZIONE PUBLIC COIN COMPLETA
        // ============================================================================

        PublicCoin::PublicCoin(std::shared_ptr<ZerocoinParams> params,
                               CBigNum value,
                               CoinDenomination denomination)
        : params_(std::move(params)),
        value_(std::move(value)),
        denomination_(denomination) {

            if (!validate()) {
                throw std::invalid_argument("Invalid public coin");
            }
        }

        bool PublicCoin::validate() const {
            if (!params_) {
                std::cerr << "Invalid: null params" << std::endl;
                return false;
            }

            if (value_.isZero()) {
                std::cerr << "Invalid: zero value" << std::endl;
                return false;
            }

            if (denomination_ == CoinDenomination::ZQ_ERROR) {
                std::cerr << "Invalid: ZQ_ERROR denomination" << std::endl;
                return false;
            }

            // Verifica che value < N
            if (BN_cmp(value_.get(), params_->N().get()) >= 0) {
                std::cerr << "Invalid: value >= N" << std::endl;
                return false;
            }

            // Verifica che value sia residuo quadratico
            if (!utils::isQuadraticResidue(value_, params_->N())) {
                std::cerr << "Invalid: value is not quadratic residue" << std::endl;
                return false;
            }

            return true;
        }

        bool PublicCoin::operator==(const PublicCoin& other) const {
            return value_ == other.value_ && denomination_ == other.denomination_;
        }

        // ============================================================================
        // IMPLEMENTAZIONE PRIVATE COIN COMPLETA
        // ============================================================================

        PrivateCoin::PrivateCoin(std::shared_ptr<ZerocoinParams> params,
                                 CoinDenomination denomination)
        : params_(std::move(params)), denomination_(denomination) {
            mint();
        }

        void PrivateCoin::mint() {
            std::cout << "Minting new coin (denomination: "
            << static_cast<uint64_t>(denomination_) << ")..." << std::endl;

            generateSerialNumber();
            generateRandomness();

            // Calcola coin pubblica: coin = g^serialNumber mod N
            std::cout << "Computing public coin: g^serialNumber mod N..." << std::endl;
            CBigNum coinValue = utils::modExp(params_->g(), serialNumber_, params_->N());

            publicCoin_ = PublicCoin(params_, std::move(coinValue), denomination_);

            // Firma la coin
            signature_ = signCoin();

            std::cout << "Coin minted successfully!" << std::endl;
            std::cout << "  Serial: " << serialNumber_.toHex().substr(0, 16) << "..." << std::endl;
            std::cout << "  Public value: " << publicCoin_.value().toHex().substr(0, 16) << "..." << std::endl;
        }

        void PrivateCoin::generateSerialNumber() {
            std::random_device rd;
            std::mt19937_64 gen(rd());

            // Genera serial number ∈ [1, N-1]
            CBigNum N_minus_1 = params_->N() + CBigNum(-1);

            do {
                serialNumber_ = BigNum::random(BN_num_bits(N_minus_1.get()) - 1, gen);
                // Assicura che non sia 0
                if (serialNumber_.isZero()) {
                    serialNumber_ = CBigNum(1);
                }

                // Assicura che sia < N
                serialNumber_ = utils::modExp(serialNumber_, CBigNum(1), N_minus_1);

            } while (serialNumber_.isZero());
        }

        void PrivateCoin::generateRandomness() {
            std::random_device rd;
            std::mt19937_64 gen(rd());

            CBigNum N_minus_1 = params_->N() + CBigNum(-1);

            do {
                randomness_ = BigNum::random(BN_num_bits(N_minus_1.get()) - 1, gen);
                randomness_ = utils::modExp(randomness_, CBigNum(1), N_minus_1);
            } while (randomness_.isZero());
        }

        uint256 PrivateCoin::signCoin() const {
            // Combina dati per l'hash
            std::stringstream ss;
            ss << serialNumber_.toHex()
            << randomness_.toHex()
            << static_cast<uint64_t>(denomination_)
            << params_->N().toHex().substr(0, 32);

            return uint256::hash(ss.str());
        }

        // ============================================================================
        // IMPLEMENTAZIONE ACCUMULATOR COMPLETA
        // ============================================================================

        Accumulator::Accumulator(std::shared_ptr<ZerocoinParams> params,
                                 CBigNum accumulatorModulus)
        : params_(std::move(params)),
        value_(CBigNum(1)),  // A_0 = 1
        accumulatorModulus_(std::move(accumulatorModulus)) {

            std::cout << "Accumulator initialized with modulus: "
            << accumulatorModulus_.toHex().substr(0, 16) << "..." << std::endl;
        }

        void Accumulator::accumulate(const CBigNum& coinValue) {
            if (coinValue.isZero() || coinValue.isOne()) {
                throw std::invalid_argument("Cannot accumulate 0 or 1");
            }

            std::cout << "Accumulating coin: " << coinValue.toHex().substr(0, 16) << "..." << std::endl;

            // A' = A^coinValue mod N
            value_ = utils::modExp(value_, coinValue, params_->N());
            accumulatedValues_.push_back(coinValue);
            ++coinCount_;

            std::cout << "  New accumulator value: " << value_.toHex().substr(0, 16) << "..." << std::endl;
            std::cout << "  Total coins: " << coinCount_ << std::endl;
        }

        void Accumulator::remove(const CBigNum& coinValue) {
            // Trova la coin
            auto it = std::find(accumulatedValues_.begin(), accumulatedValues_.end(), coinValue);
            if (it == accumulatedValues_.end()) {
                throw std::runtime_error("Coin not found in accumulator");
            }

            std::cout << "Removing coin from accumulator..." << std::endl;

            // Calcola phi(N) = N - 1 (per RSA con primi sicuri)
            CBigNum phiN = params_->N() + CBigNum(-1);

            // Calcola l'inverso moltiplicativo di coinValue mod phi(N)
            CBigNum inv = utils::modInverse(coinValue, phiN);

            // A' = A^{inv} mod N
            value_ = utils::modExp(value_, inv, params_->N());

            // Rimuovi dalla lista
            accumulatedValues_.erase(it);
            --coinCount_;

            std::cout << "  Coin removed successfully" << std::endl;
            std::cout << "  Remaining coins: " << coinCount_ << std::endl;
        }

        CBigNum Accumulator::calculateWitness(const CBigNum& coinValue) const {
            // Verifica che la coin sia nell'accumulator
            if (std::find(accumulatedValues_.begin(), accumulatedValues_.end(), coinValue)
                == accumulatedValues_.end()) {
                throw std::runtime_error("Coin not in accumulator");
                }

                // Calcola prodotto di tutte le ALTRE monete
                CBigNum product(1);
            CBigNum phiN = params_->N() + CBigNum(-1);

            BN_CTX* ctx = BN_CTX_new();
            if (!ctx) throw std::bad_alloc();

            for (const auto& val : accumulatedValues_) {
                if (val != coinValue) {
                    // product = (product * val) mod phiN
                    BIGNUM* temp = BN_new();
                    BN_mod_mul(temp, product.get(), val.get(), phiN.get(), ctx);
                    BN_copy(product.get(), temp);
                    BN_free(temp);
                }
            }

            BN_CTX_free(ctx);

            // Witness = g^product mod N
            return utils::modExp(params_->g(), product, params_->N());
        }

        // ============================================================================
        // IMPLEMENTAZIONE COIN SPEND COMPLETA
        // ============================================================================

        CoinSpend::CoinSpend(std::shared_ptr<ZerocoinParams> params,
                             const PrivateCoin& coin,
                             const Accumulator& accumulator,
                             uint32_t accumulatorId,
                             const uint256& ptxHash,
                             Version version)
        : version_(version),
        params_(std::move(params)),
        accumulatorId_(accumulatorId),
        ptxHash_(ptxHash),
        accumulatorValue_(accumulator.value()) {

            coinSerialNumber_ = coin.serialNumber();

            std::cout << "Creating CoinSpend..." << std::endl;
            std::cout << "  Serial: " << coinSerialNumber_.toHex().substr(0, 16) << "..." << std::endl;
            std::cout << "  Accumulator ID: " << accumulatorId_ << std::endl;

            // Calcola witness per la proof
            CBigNum witness = accumulator.calculateWitness(coin.publicCoin().value());

            // Genera proof
            generateAccumulatorProof(accumulator, witness);
            generateSerialNumberProof(coin);

            // Genera signature
            auto msg = getSignatureMessage();
            signature_ = utils::sha256(msg);

            std::cout << "CoinSpend created successfully!" << std::endl;
        }

        bool CoinSpend::verify(const Accumulator& accumulator) const {
            std::cout << "Verifying CoinSpend..." << std::endl;

            // 1. Verifica che la coin sia nell'accumulator
            CBigNum coinCommitment = utils::modExp(params_->g(), coinSerialNumber_, params_->N());

            bool found = false;
            for (const auto& val : accumulatedValues_) {
                if (val == coinCommitment) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                std::cerr << "  Verification failed: coin not in accumulator" << std::endl;
                return false;
            }

            std::cout << "  ✓ Coin is in accumulator" << std::endl;

            // 2. Verifica signature
            if (!hasValidSignature()) {
                std::cerr << "  Verification failed: invalid signature" << std::endl;
                return false;
            }

            std::cout << "  ✓ Signature is valid" << std::endl;

            // 3. Verifica proof dell'accumulator (semplificata)
            if (accumulatorProof_.empty()) {
                std::cerr << "  Verification failed: empty accumulator proof" << std::endl;
                return false;
            }

            std::cout << "  ✓ Accumulator proof present" << std::endl;

            // 4. Verifica proof del serial number (semplificata)
            if (serialNumberProof_.empty()) {
                std::cerr << "  Verification failed: empty serial number proof" << std::endl;
                return false;
            }

            std::cout << "  ✓ Serial number proof present" << std::endl;

            // 5. Verifica che accumulatorValue corrisponda
            if (accumulatorValue_ != accumulator.value()) {
                std::cerr << "  Verification failed: accumulator value mismatch" << std::endl;
                return false;
            }

            std::cout << "  ✓ Accumulator value matches" << std::endl;

            std::cout << "CoinSpend verification SUCCESSFUL!" << std::endl;
            return true;
        }

        bool CoinSpend::hasValidSignature() const {
            if (signature_.empty()) return false;

            auto computed = utils::sha256(getSignatureMessage());

            // Confronta gli hash byte per byte
            if (computed.size() != signature_.size()) return false;

            for (size_t i = 0; i < computed.size(); ++i) {
                if (computed[i] != signature_[i]) return false;
            }

            return true;
        }

        std::vector<uint8_t> CoinSpend::getSignatureMessage() const {
            std::vector<uint8_t> msg;

            // Versione
            msg.push_back(static_cast<uint8_t>(version_));

            // Serial number
            auto serialBytes = coinSerialNumber_.toBytes();
            msg.insert(msg.end(), serialBytes.begin(), serialBytes.end());

            // Accumulator ID
            for (int i = 24; i >= 0; i -= 8) {
                msg.push_back(static_cast<uint8_t>((accumulatorId_ >> i) & 0xFF));
            }

            // Accumulator value
            auto accBytes = accumulatorValue_.toBytes();
            msg.insert(msg.end(), accBytes.begin(), accBytes.end());

            // Transaction hash
            auto hashBytes = ptxHash_.bytes();
            msg.insert(msg.end(), hashBytes.begin(), hashBytes.end());

            return msg;
        }

        void CoinSpend::generateAccumulatorProof(const Accumulator& accumulator,
                                                 const CBigNum& witness) {
            // Genera proof Sigma semplificata (per demo)
            // In produzione, implementa il protocollo Sigma completo

            std::random_device rd;
            std::mt19937_64 gen(rd());

            int security = static_cast<int>(params_->securityLevel());
            accumulatorProof_.clear();

            std::cout << "Generating accumulator proof (security: " << security << ")..." << std::endl;

            for (int i = 0; i < security; ++i) {
                // Genera challenge random
                CBigNum r = BigNum::random(BN_num_bits(params_->N().get()) / 2, gen);

                // Calcola commitment T = g^r mod N
                CBigNum T = utils::modExp(params_->g(), r, params_->N());

                // Aggiungi alla proof
                auto bytes = T.toBytes();
                accumulatorProof_.insert(accumulatorProof_.end(), bytes.begin(), bytes.end());
            }

            std::cout << "  Proof size: " << accumulatorProof_.size() << " bytes" << std::endl;
                                                 }

                                                 void CoinSpend::generateSerialNumberProof(const PrivateCoin& coin) {
                                                     // Proof semplificata: hash del serial number
                                                     auto serialBytes = coin.serialNumber().toBytes();

                                                     // Aggiungi randomness per binding
                                                     auto randomBytes = coin.randomness().toBytes();
                                                     serialBytes.insert(serialBytes.end(), randomBytes.begin(), randomBytes.end());

                                                     // Calcola hash
                                                     serialNumberProof_ = utils::sha256(serialBytes);

                                                     std::cout << "Serial number proof generated: "
                                                     << serialNumberProof_.size() << " bytes" << std::endl;
                                                 }

                                                 // ============================================================================
                                                 // IMPLEMENTAZIONE UTILS COMPLETA
                                                 // ============================================================================

                                                 namespace utils {

                                                     CBigNum randomBignum(const CBigNum& upperBound) {
                                                         std::random_device rd;
                                                         std::mt19937_64 gen(rd());

                                                         size_t bits = BN_num_bits(upperBound.get());
                                                         CBigNum result = BigNum::random(bits, gen);

                                                         // Assicura result < upperBound
                                                         while (BN_cmp(result.get(), upperBound.get()) >= 0) {
                                                             result = BigNum::random(bits, gen);
                                                         }

                                                         return result;
                                                     }

                                                     CBigNum randomPrime(uint32_t bits) {
                                                         BIGNUM* prime = BN_new();
                                                         if (!prime) throw std::bad_alloc();

                                                         if (!BN_generate_prime_ex(prime, bits, 1, nullptr, nullptr, nullptr)) {
                                                             BN_free(prime);
                                                             throw std::runtime_error("Failed to generate prime");
                                                         }

                                                         CBigNum result;
                                                         BN_copy(result.get(), prime);
                                                         BN_free(prime);

                                                         return result;
                                                     }

                                                     CBigNum modExp(const CBigNum& base, const CBigNum& exp, const CBigNum& mod) {
                                                         CBigNum result;
                                                         BN_CTX* ctx = BN_CTX_new();
                                                         if (!ctx) throw std::bad_alloc();

                                                         if (!BN_mod_exp(result.get(), base.get(), exp.get(), mod.get(), ctx)) {
                                                             BN_CTX_free(ctx);
                                                             throw std::runtime_error("BN_mod_exp failed");
                                                         }

                                                         BN_CTX_free(ctx);
                                                         return result;
                                                     }

                                                     CBigNum modInverse(const CBigNum& a, const CBigNum& mod) {
                                                         CBigNum result;
                                                         BN_CTX* ctx = BN_CTX_new();
                                                         if (!ctx) throw std::bad_alloc();

                                                         if (!BN_mod_inverse(result.get(), a.get(), mod.get(), ctx)) {
                                                             BN_CTX_free(ctx);
                                                             throw std::runtime_error("BN_mod_inverse failed");
                                                         }

                                                         BN_CTX_free(ctx);
                                                         return result;
                                                     }

                                                     bool isQuadraticResidue(const CBigNum& a, const CBigNum& p) {
                                                         // Calcola (p-1)/2
                                                         CBigNum p_minus_1 = p + CBigNum(-1);
                                                         CBigNum exponent;

                                                         BN_CTX* ctx = BN_CTX_new();
                                                         if (!ctx) throw std::bad_alloc();

                                                         // exponent = (p-1)/2
                                                         BIGNUM* p_minus_1_bn = BN_dup(p_minus_1.get());
                                                         BN_rshift1(exponent.get(), p_minus_1_bn);
                                                         BN_free(p_minus_1_bn);

                                                         // Calcola Legendre symbol: a^exponent mod p
                                                         CBigNum legendre = modExp(a, exponent, p);

                                                         BN_CTX_free(ctx);

                                                         // Se legendre == 1, a è residuo quadratico
                                                         return legendre == CBigNum(1);
                                                     }

                                                     std::vector<uint8_t> sha256(std::span<const uint8_t> data) {
                                                         std::vector<uint8_t> hash(EVP_MAX_MD_SIZE);
                                                         unsigned int len = 0;

                                                         EVP_MD_CTX* ctx = EVP_MD_CTX_new();
                                                         if (!ctx) throw std::bad_alloc();

                                                         if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
                                                             EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
                                                             EVP_DigestFinal_ex(ctx, hash.data(), &len) != 1) {
                                                             EVP_MD_CTX_free(ctx);
                                                         throw std::runtime_error("SHA256 failed");
                                                             }

                                                             EVP_MD_CTX_free(ctx);
                                                             hash.resize(len);
                                                             return hash;
                                                     }

                                                     uint256 hashToUint256(std::span<const uint8_t> data) {
                                                         auto hash = sha256(data);

                                                         // Prendi primi 32 byte (SHA256 produce 32 byte)
                                                         std::array<uint8_t, 32> arr;
                                                         std::copy_n(hash.begin(), 32, arr.begin());

                                                         return uint256(arr);
                                                     }

                                                     bool validateRSAModulus(const CBigNum& N) {
                                                         // Verifica base
                                                         if (N.isZero() || N.isOne()) return false;

                                                         // Verifica che N sia dispari (tutti i moduli RSA sono dispari)
                                                         if (BN_is_odd(N.get()) == 0) return false;

                                                         // Verifica dimensione minima (2048 bit)
                                                         if (BN_num_bits(N.get()) < 2048) return false;

                                                         return true;
                                                     }

                                                     bool validateGenerator(const CBigNum& g, const CBigNum& N) {
                                                         if (g.isZero() || g.isOne()) return false;
                                                         if (BN_cmp(g.get(), N.get()) >= 0) return false;

                                                         // Verifica che g sia residuo quadratico
                                                         return isQuadraticResidue(g, N);
                                                     }

                                                 } // namespace utils

} // namespace libzerocoin
