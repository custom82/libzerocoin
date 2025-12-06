#ifndef ACCUMULATOR_H
#define ACCUMULATOR_H

#include "Bignum.h"
#include "Stream.h"
#include "AccumulatorWitness.h"

namespace libzerocoin {

	class Accumulator {
	public:
		Accumulator(const IntegerGroupParams* p, const Bignum& value);
		void Add(const Bignum& value);
		void Serialize(Stream& s) const;
		void Unserialize(Stream& s);

	private:
		Bignum accumulatorValue;
		const IntegerGroupParams* params;
	};

}

#endif // ACCUMULATOR_H
