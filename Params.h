#ifndef LIBZEROCOIN_PARAMS_H
#define LIBZEROCOIN_PARAMS_H

#include "src/serialize_stub.h"
#include "src/zerocoin_types.h"
#include "bitcoin_bignum/bignum.h"

namespace libzerocoin {

	// Gruppi di impegno: moduli RSA / DLP per protocolli Zerocoin
	struct IntegerGroupParams
	{
		CBigNum modulus;
		CBigNum groupOrder;
		CBigNum g;
		CBigNum h;

		ADD_SERIALIZE_METHODS;
	};

	// Parametri per accumulatori e prove di conoscenza
	struct AccumulatorAndProofParams
	{
		CBigNum accumulatorModulus;

		IntegerGroupParams accumulatorPoKCommitmentGroup;
		IntegerGroupParams accumulatorQRNCommitmentGroup;

		CBigNum maxCoinValue;
		int k_prime;
		int k_dprime;

		ADD_SERIALIZE_METHODS;
	};

	// Root params Zerocoin
	struct ZerocoinParams
	{
		IntegerGroupParams coinCommitmentGroup;
		IntegerGroupParams serialNumberSoKCommitmentGroup;
		AccumulatorAndProofParams accumulatorParams;

		ADD_SERIALIZE_METHODS;
	};

} // namespace libzerocoin

#endif
