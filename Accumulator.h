#ifndef LIBZEROCOIN_ACCUMULATOR_H
#define LIBZEROCOIN_ACCUMULATOR_H

#include <vector>
#include "bignum.h"  // Include per CBigNum
#include "Coin.h"
#include "Params.h"

namespace libzerocoin
{

	class Accumulator
	{
	private:
		CBigNum value;  // Modificato per usare CBigNum
		// Altri membri...

	public:
		Accumulator(const AccumulatorAndProofParams* p, int denomination);
		// Altri metodi...

		CBigNum getValue() const { return value; } // Funzione per ottenere il valore
	};

} // namespace libzerocoin

#endif // LIBZEROCOIN_ACCUMULATOR_H
