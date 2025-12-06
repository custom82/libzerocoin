#ifndef ZEROCOIN_TYPES_H
#define ZEROCOIN_TYPES_H

#include "bignum.h"
#include <string>
#include <vector>

namespace libzerocoin {

    // Forward declarations
    class Stream;
    class IntegerGroupParams;
    class ZerocoinParams;
    class Params;
    class AccumulatorAndProofParams;
    class Commitment;
    class CommitmentProofOfKnowledge;
    class Accumulator;
    class AccumulatorWitness;
    class PublicCoin;
    class PrivateCoin;
    class CoinSpend;
    class SpendMetaData;

    // Tipi di monete
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

    // Tipo Bignum (alias per CBigNum)
    typedef CBigNum Bignum;

    // Hash type
    typedef std::vector<unsigned char> uint256;

    // Parametri del gruppo
    class IntegerGroupParams {
    public:
        Bignum g;
        Bignum h;
        Bignum modulus;
        Bignum groupOrder;

        IntegerGroupParams();

        Bignum randomElement() const;
        Bignum groupModulus() const { return modulus; }
        Bignum getG() const { return g; }
        Bignum getH() const { return h; }
    };

    // Parametri accumulatore
    class AccumulatorAndProofParams {
    public:
        IntegerGroupParams accumulatorQRN;
        IntegerGroupParams accumulatorBase;

        AccumulatorAndProofParams();
    };

    // Parametri principali Zerocoin
    class ZerocoinParams {
    public:
        IntegerGroupParams coinCommitmentGroup;
        IntegerGroupParams serialNumberSoKCommitmentGroup;
        AccumulatorAndProofParams accumulatorParams;
        Bignum accumulatorModulus;
        int securityLevel;

        ZerocoinParams(const Bignum& N, uint32_t securityLevel);
    };

    // Alias per compatibilità
    typedef ZerocoinParams Params;

    // Stream interface (astratta)
    class Stream {
    public:
        virtual ~Stream() {}
        virtual void write(const char* pch, size_t nSize) = 0;
        virtual void read(char* pch, size_t nSize) = 0;
    };

} // namespace libzerocoin

#endif
