#include "Accumulator.h"

namespace libzerocoin {

	Accumulator::Accumulator(const IntegerGroupParams* p, const Bignum& value)
	: params(p), value(value) {
	}

	void Accumulator::Add(const Bignum& value) {
		// In una implementazione reale: value = (value * newValue) mod modulus
		this->value = this->value + value;  // Stub semplificato
	}

	template<typename Stream>
	void Accumulator::Serialize(Stream& s) const {
		// Stub
	}

	template<typename Stream>
	void Accumulator::Unserialize(Stream& s) {
		// Stub
	}

} // namespace libzerocoin
