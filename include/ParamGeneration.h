#ifndef PARAM_GENERATION_H
#define PARAM_GENERATION_H

#include "bignum.h"
#include "serialize.h"

class IntegerGroupParams {
public:
    CBigNum modulus;
    CBigNum groupOrder;
    CBigNum g;
    CBigNum h;
};


class AccumulatorAndProofParams {
public:
    CBigNum accumulatorModulus;
    CBigNum accumulatorBase;
    CBigNum minCoinValue;
    CBigNum maxCoinValue;
    CBigNum accumulatorPoKCommitmentGroupG;
    CBigNum accumulatorPoKCommitmentGroupH;
    uint32_t k_prime;
    uint32_t k_dprime;
};


class ZerocoinParams {
public:
    bool initialized;
    uint32_t securityLevel;
    AccumulatorAndProofParams accumulatorParams;
    IntegerGroupParams coinCommitmentGroup;
    IntegerGroupParams serialNumberSoKCommitmentGroup;
};


#endif
