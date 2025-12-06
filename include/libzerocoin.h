#ifndef LIBZEROCOIN_H
#define LIBZEROCOIN_H

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <memory>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <sstream>

namespace libzerocoin {

// ============================================================================
// Forward declarations and basic types
// ============================================================================

class uint256;
class CBigNum;
class IntegerGroupParams;
class ZerocoinParams;
class Accumulator;
class AccumulatorWitness;
class AccumulatorProofOfKnowledge;
class SerialNumberSignatureOfKnowledge;
class PublicCoin;
class PrivateCoin;
class Commitment;
class CoinSpend;
class SpendMetaData;

// Coin denominations
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

// ============================================================================
// uint256 - Simple 256-bit hash
// ============================================================================

class uint256 {
private:
    unsigned char data[32];

public:
    uint256() { memset(data, 0, sizeof(data)); }

    uint256(const std::vector<unsigned char>& vch) {
        if (vch.size() == 32) {
            memcpy(data, vch.data(), 32);
        } else {
            memset(data, 0, sizeof(data));
        }
    }

    bool IsNull() const {
        for (int i = 0; i < 32; i++) {
            if (data[i] != 0) return false;
        }
        return true;
    }

    bool operator==(const uint256& b) const {
        return memcmp(data, b.data, 32) == 0;
    }

    bool operator!=(const uint256& b) const {
        return memcmp(data, b.data, 32) != 0;
    }

    const unsigned char* begin() const { return data; }
    const unsigned char* end() const { return data + 32; }
};

// ============================================================================
// CBigNum - Big number wrapper for OpenSSL BIGNUM
// ============================================================================

class CBigNum {
private:
    BIGNUM* bignum;
    static BN_CTX* ctx;

public:
    // Constructors
    CBigNum();
    CBigNum(const CBigNum& b);
    explicit CBigNum(long long n);
    ~CBigNum();

    // Assignment
    CBigNum& operator=(const CBigNum& b);

    // Arithmetic operators
    CBigNum operator+(const CBigNum& b) const;
    CBigNum operator-(const CBigNum& b) const;
    CBigNum operator*(const CBigNum& b) const;
    CBigNum operator/(const CBigNum& b) const;
    CBigNum operator%(const CBigNum& b) const;

    // Comparison operators
    friend bool operator==(const CBigNum& a, const CBigNum& b);
    friend bool operator!=(const CBigNum& a, const CBigNum& b);
    friend bool operator<=(const CBigNum& a, const CBigNum& b);
    friend bool operator>=(const CBigNum& a, const CBigNum& b);
    friend bool operator<(const CBigNum& a, const CBigNum& b);
    friend bool operator>(const CBigNum& a, const CBigNum& b);

    // Static methods
    static CBigNum generatePrime(unsigned int numBits, bool safe = false);
    static CBigNum randBignum(const CBigNum& range);
    static CBigNum randKBitBignum(uint32_t k);

    // Methods
    CBigNum sha256() const;
    void setvch(const std::vector<unsigned char>& vch);
    std::vector<unsigned char> getvch() const;
    std::string ToString(int nBase = 10) const;

    // Access to internal BIGNUM
    const BIGNUM* getBN() const { return bignum; }
    BIGNUM* getBN() { return bignum; }
};

// Comparison operators
bool operator==(const CBigNum& a, const CBigNum& b);
bool operator!=(const CBigNum& a, const CBigNum& b);
bool operator<=(const CBigNum& a, const CBigNum& b);
bool operator>=(const CBigNum& a, const CBigNum& b);
bool operator<(const CBigNum& a, const CBigNum& b);
bool operator>(const CBigNum& a, const CBigNum& b);

// ============================================================================
// Hash functions
// ============================================================================

uint256 Hash(const std::vector<unsigned char>& vch);
uint256 Hash(const std::string& str);
uint256 Hash(const uint256& hash);

// ============================================================================
// IntegerGroupParams
// ============================================================================

class IntegerGroupParams {
public:
    CBigNum g;
    CBigNum h;
    CBigNum p;
    CBigNum q;
    CBigNum groupOrder;

    IntegerGroupParams();
    ~IntegerGroupParams() = default;

    CBigNum randomElement() const;
};

// ============================================================================
// ZerocoinParams
// ============================================================================

class ZerocoinParams {
public:
    IntegerGroupParams coinCommitmentGroup;
    IntegerGroupParams serialNumberSoKCommitmentGroup;
    IntegerGroupParams accumulatorParams;

    uint32_t accumulatorParamsMinPrimeLength;
    uint32_t ZK_iterations;
    uint32_t securityLevel;

    ZerocoinParams();
    ~ZerocoinParams() = default;
};

// ============================================================================
// Accumulator
// ============================================================================

class Accumulator {
private:
    const IntegerGroupParams* params;
    CBigNum value;

public:
    Accumulator(const IntegerGroupParams* p, const CBigNum& val);
    ~Accumulator() = default;

    void Add(const CBigNum& val);
    CBigNum getValue() const { return value; }
    const IntegerGroupParams* getParams() const { return params; }
};

class AccumulatorWitness {
private:
    const Accumulator* accumulator;
    CBigNum element;
    CBigNum witness;

public:
    AccumulatorWitness(const Accumulator* acc, const CBigNum& elem);
    ~AccumulatorWitness() = default;

    void AddElement(const CBigNum& elem);
    CBigNum getValue() const { return witness; }
};

// ============================================================================
// Proofs (simplified)
// ============================================================================

class AccumulatorProofOfKnowledge {
public:
    AccumulatorProofOfKnowledge() = default;
    ~AccumulatorProofOfKnowledge() = default;

    bool Verify() const { return true; } // Simplified
};

class SerialNumberSignatureOfKnowledge {
public:
    SerialNumberSignatureOfKnowledge() = default;
    ~SerialNumberSignatureOfKnowledge() = default;

    bool Verify() const { return true; } // Simplified
};

// ============================================================================
// Commitment
// ============================================================================

class Commitment {
private:
    const IntegerGroupParams* params;
    CBigNum commitment;

public:
    Commitment(const IntegerGroupParams* p, const CBigNum& value, const CBigNum& randomness);
    ~Commitment() = default;

    CBigNum getCommitmentValue() const { return commitment; }
    const IntegerGroupParams* getParams() const { return params; }

    bool operator==(const Commitment& rhs) const {
        return commitment == rhs.commitment;
    }

    bool operator!=(const Commitment& rhs) const {
        return !(*this == rhs);
    }
};

// ============================================================================
// Coin classes
// ============================================================================

class PublicCoin {
private:
    const ZerocoinParams* params;
    CBigNum value;
    CoinDenomination denomination;

public:
    PublicCoin() : params(nullptr), denomination(ZQ_ERROR) {}
    PublicCoin(const ZerocoinParams* p, const CBigNum& v, CoinDenomination d)
        : params(p), value(v), denomination(d) {}

    const CBigNum& getValue() const { return value; }
    CoinDenomination getDenomination() const { return denomination; }
    const ZerocoinParams* getParams() const { return params; }
};

class PrivateCoin {
private:
    const ZerocoinParams* params;
    CBigNum serialNumber;
    CBigNum randomness;
    PublicCoin publicCoin;
    CoinDenomination denomination;
    uint8_t version;

public:
    PrivateCoin(const ZerocoinParams* p, CoinDenomination d);

    const CBigNum& getSerialNumber() const { return serialNumber; }
    const CBigNum& getRandomness() const { return randomness; }
    const PublicCoin& getPublicCoin() const { return publicCoin; }
    CoinDenomination getDenomination() const { return denomination; }
    uint8_t getVersion() const { return version; }
};

// ============================================================================
// CoinSpend
// ============================================================================

class CoinSpend {
private:
    CoinDenomination denomination;
    uint32_t accChecksum;
    CBigNum coinSerialNumber;
    CBigNum accumulatorCommitment;
    std::unique_ptr<AccumulatorProofOfKnowledge> accumulatorProofOfKnowledge;
    std::unique_ptr<SerialNumberSignatureOfKnowledge> serialNumberSignatureOfKnowledge;
    uint256 ptxHash;
    unsigned char version;
    uint8_t bytes[192];
    int32_t txVersion;

public:
    CoinSpend() = default;
    CoinSpend(const ZerocoinParams* params, const PrivateCoin& coin,
              Accumulator& a, const uint32_t& checksum,
              const AccumulatorWitness& witness, const uint256& ptxHash);
    ~CoinSpend() = default;

    const CBigNum& getCoinSerialNumber() const { return coinSerialNumber; }
    const uint256 getTxOutHash() const { return ptxHash; }
    const uint32_t getAccumulatorChecksum() const { return accChecksum; }
    const CoinDenomination getDenomination() const { return denomination; }
    const unsigned char getVersion() const { return version; }
    bool HasValidSerial(ZerocoinParams* params) const;
};

// ============================================================================
// SpendMetaData
// ============================================================================

class SpendMetaData {
private:
    uint256 accumulatorId;
    uint256 txHash;

public:
    SpendMetaData() = default;
    SpendMetaData(uint256 accumulatorId, uint256 txHash);
    ~SpendMetaData() = default;

    const uint256& getAccumulatorId() const { return accumulatorId; }
    const uint256& getTxHash() const { return txHash; }

    void setAccumulatorId(const uint256& id) { accumulatorId = id; }
    void setTxHash(const uint256& hash) { txHash = hash; }
};

// ============================================================================
// Parameter generation
// ============================================================================

IntegerGroupParams* CalculateParams(IntegerGroupParams &result, CBigNum N, CBigNum seed,
                                    uint32_t pLen, uint32_t qLen);

} // namespace libzerocoin

#endif // LIBZEROCOIN_H
