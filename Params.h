#ifndef LIBZEROCOIN_PARAMS_H
#define LIBZEROCOIN_PARAMS_H

#include "src/serialize_stub.h"
#include "src/zerocoin_types.h"
#include "bitcoin_bignum/bignum.h"

namespace libzerocoin {

	struct IntegerGroupParams
	{
		CBigNum modulus;
		CBigNum groupOrder;
		CBigNum g;
		CBigNum h;
	};

	struct AccumulatorAndProofParams
	{
		CBigNum accumulatorModulus;
	};

	struct ZerocoinParams
	{
		IntegerGroupParams coinCommitmentGroup;
		IntegerGroupParams serialNumberSoKCommitmentGroup;
		AccumulatorAndProofParams accumulatorParams;
		unsigned int zk_bits;
		unsigned int zkp_iterations;
	};

}

#endif
