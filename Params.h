#ifndef PARAMS_H
#define PARAMS_H

#include "bitcoin_bignum/bignum.h"

namespace libzerocoin {

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

		ZerocoinParams() : initialized(false), securityLevel(80) {}
	};

}

#endif
