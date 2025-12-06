#ifndef ZEROCOIN_DEFS_H
#define ZEROCOIN_DEFS_H

#include "bignum.h"
#include <cstdint>
#include <string>
#include <vector>

namespace libzerocoin {

    // Forward declarations
    class IntegerGroupParams;
    class AccumulatorAndProofParams;
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

    // Usa using invece di typedef
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
        bool initialized;

        IntegerGroupParams();
        Bignum randomElement() const;
    };

    // Parametri accumulatore
    class AccumulatorAndProofParams {
    public:
        IntegerGroupParams accumulatorQRN;
        IntegerGroupParams accumulatorBase;
        bool initialized;

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
    };

} // namespace libzerocoin

#endif
