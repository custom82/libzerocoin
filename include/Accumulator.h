#ifndef ACCUMULATOR_H
#define ACCUMULATOR_H

#include "zerocoin_defs.h"

namespace libzerocoin {

	class Accumulator {
	public:
		Accumulator(const IntegerGroupParams* p, const Bignum& value);

		void Add(const Bignum& value);
		Bignum getValue() const { return value; }

		// Serializzazione
		template<typename Stream>
		void Serialize(Stream& s) const;

		template<typename Stream>
		void Unserialize(Stream& s);

	private:
		const IntegerGroupParams* params;
		Bignum value;
	};

} // namespace libzerocoin

#endif
