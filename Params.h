#ifndef LIBZEROCOIN_PARAMS_H
#define LIBZEROCOIN_PARAMS_H

#include "bignum.h"  // Aggiungiamo l'inclusione di CBigNum

namespace libzerocoin
{

	// Parametri per Accumulatore
	struct AccumulatorAndProofParams
	{
		CBigNum accumulatorModulus;  // Usa CBigNum
		// Altri parametri...

		// Funzioni per la serializzazione...
	};

} // namespace libzerocoin

#endif // LIBZEROCOIN_PARAMS_H
