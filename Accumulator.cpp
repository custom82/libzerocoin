#include "Accumulator.h"

namespace libzerocoin {

	Accumulator::Accumulator(const IntegerGroupParams* p, const Bignum& value) {
		this->params = p;
		this->accumulatorValue = value;
	}

	void Accumulator::Add(const Bignum& value) {
		this->accumulatorValue += value;  // Aggiunta del valore all'accumulatore
	}

	void Accumulator::Serialize(Stream& s) const {
		s << accumulatorValue;
	}

	void Accumulator::Unserialize(Stream& s) {
		s >> accumulatorValue;
	}

}
