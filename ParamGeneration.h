#ifndef PARAM_GENERATION_H
#define PARAM_GENERATION_H

#include "bitcoin_bignum/bignum.h"
#include "serialize.h"

struct IntegerGroupParams
{
    CBigNum modulus;
    CBigNum groupOrder;
    CBigNum g;
    CBigNum h;

    bool validate() const;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(modulus);
        READWRITE(groupOrder);
        READWRITE(g);
        READWRITE(h);
    )
};

struct AccumulatorAndProofParams
{
    CBigNum accumulatorModulus;
    CBigNum accumulatorBase;
    CBigNum minCoinValue;
    CBigNum maxCoinValue;
    IntegerGroupParams accumulatorPoKCommitmentGroupG;
    IntegerGroupParams accumulatorPoKCommitmentGroupH;

    uint32_t k_prime;
    uint32_t k_dprime;

    bool validate() const;

    IMPLEMENT_SERIALIZE
    (
        READWRITE(accumulatorModulus);
        READWRITE(accumulatorBase);
        READWRITE(minCoinValue);
        READWRITE(maxCoinValue);
        READWRITE(accumulatorPoKCommitmentGroupG);
        READWRITE(accumulatorPoKCommitmentGroupH);
        READWRITE(k_prime);
        READWRITE(k_dprime);
    )
};

class ZerocoinParams
{
public:
    uint32_t initialized;
    uint32_t securityLevel;

    AccumulatorAndProofParams accumulatorParams;
    IntegerGroupParams coinCommitmentGroup;
    IntegerGroupParams serialNumberSoKCommitmentGroup;

    static ZerocoinParams* LoadFromFile(const std::string& filepath);

    IMPLEMENT_SERIALIZE
    (
        READWRITE(initialized);
        READWRITE(securityLevel);
        READWRITE(accumulatorParams);
        READWRITE(coinCommitmentGroup);
        READWRITE(serialNumberSoKCommitmentGroup);
    )
};

#endif
