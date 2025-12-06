#ifndef ZEROCOIN_DEFS_H
#define ZEROCOIN_DEFS_H

#include "bignum.h"
#include <cstdint>
#include <string>
#include <vector>

namespace libzerocoin {

    // Forward declarations
    class IntegerGroupParams;
    class ZerocoinParams;
    class Params;
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

    // Tipi di base
    typedef CBigNum Bignum;
    typedef std::vector<unsigned char> uint256;

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
    };

    // Alias
    typedef ZerocoinParams Params;

} // namespace libzerocoin

#endif
