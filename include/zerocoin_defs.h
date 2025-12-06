#ifndef ZEROCOIN_DEFS_H
#define ZEROCOIN_DEFS_H

#include "bignum.h"
#include <cstdint>
#include <string>
#include <vector>

// Forward declarations in global namespace
class CAccumulatorWitness;

namespace libzerocoin {

    // Forward declarations
    class IntegerGroupParams;
    class ZerocoinParams;
    class Accumulator;
    class AccumulatorWitness;
    class Commitment;
    class CommitmentProofOfKnowledge;
    class PublicCoin;
    class PrivateCoin;
    class CoinSpend;
    class AccumulatorProofOfKnowledge;
    class SerialNumberSignatureOfKnowledge;
    class SpendMetaData;

    // Usa using invece di typedef per evitare conflitti
    using Params = ZerocoinParams;

    // Tipi di base
    using Bignum = CBigNum;
    using uint256 = std::vector<unsigned char>;

    // Denominazioni delle monete
    enum CoinDenomination {
        ZQ_ERROR = 0,
        ZQ_ONE = 1,
        ZQ_FIVE = 5,
        ZQ_TEN = 10,
        ZQ_FIFTY = 50,
        ZQ_ONE_HUNDRED = 100,
        ZQ_FIVE_HUNDRED = 500,
        ZQ_ONE_THOUSAND = 1000
    };

    // Parametri del gruppo
    class IntegerGroupParams {
    public:
        Bignum g;
        Bignum h;
        Bignum modulus;
        Bignum groupOrder;

        IntegerGroupParams();
        Bignum randomElement() const;
        Bignum getG() const { return g; }
        Bignum getH() const { return h; }
        Bignum getModulus() const { return modulus; }
    };

    // Parametri accumulatore
    class AccumulatorAndProofParams {
    public:
        IntegerGroupParams accumulatorQRN;
        IntegerGroupParams accumulatorBase;

        AccumulatorAndProofParams();
    };

    // Parametri principali
    class ZerocoinParams {
    public:
        IntegerGroupParams coinCommitmentGroup;
        IntegerGroupParams serialNumberSoKCommitmentGroup;
        AccumulatorAndProofParams accumulatorParams;
        Bignum accumulatorModulus;
        int securityLevel;

        ZerocoinParams(const Bignum& N, uint32_t securityLevel);

        // Getters
        const IntegerGroupParams& getCoinCommitmentGroup() const { return coinCommitmentGroup; }
        const IntegerGroupParams& getSerialNumberSoKCommitmentGroup() const { return serialNumberSoKCommitmentGroup; }
        const AccumulatorAndProofParams& getAccumulatorParams() const { return accumulatorParams; }
        const Bignum& getAccumulatorModulus() const { return accumulatorModulus; }
        int getSecurityLevel() const { return securityLevel; }
    };

} // namespace libzerocoin

#endif
