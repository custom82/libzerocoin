#ifndef LIBZEROCOIN_PARAMS_H
#define LIBZEROCOIN_PARAMS_H

#include "bignum.h"  // Aggiungi CBigNum

namespace libzerocoin
{

	struct ZerocoinParams
	{
		CBigNum accumulatorModulus;  // Usa CBigNum
		// Altri parametri...
	};

	struct IntegerGroupParams
	{
		CBigNum modulus;
		// Altri parametri...
	};

	struct AccumulatorAndProofParams
	{
		CBigNum accumulatorModulus;  // Usa CBigNum
		// Altri parametri...
	};

} // namespace libzerocoin

#endif // LIBZEROCOIN_PARAMS_H
