#include "Accumulator.h"

namespace libzerocoin {

	Accumulator::Accumulator(const IntegerGroupParams* p, const Bignum& value)
	: params(p), value(value) {
	}

	void Accumulator::Add(const Bignum& value) {
		// Stub: in realtà sarebbe una moltiplicazione modulare
		this->value = this->value + value;
	}

} // namespace libzerocoin
