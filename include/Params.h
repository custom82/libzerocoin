#ifndef PARAMS_H
#define PARAMS_H

#include "bignum.h"
#include "zerocoin_defs.h"
#include <vector>

namespace libzerocoin {

    class IntegerGroupParams {
    public:
        CBigNum g, h, p, q;
        CBigNum groupOrder;

        IntegerGroupParams() = default;
        ~IntegerGroupParams() = default;
    };

    class ZerocoinParams {
    public:
        IntegerGroupParams coinCommitmentGroup;
        IntegerGroupParams serialNumberSoKCommitmentGroup;
        IntegerGroupParams accumulatorParams;

        uint32_t accumulatorParamsMinPrimeLength;
        uint32_t ZK_iterations;
        uint32_t securityLevel;

        ZerocoinParams() = default;
        ~ZerocoinParams() = default;
    };

} // namespace libzerocoin

#endif // PARAMS_H
