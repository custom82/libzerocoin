#ifndef ZEROCOIN_H
#define ZEROCOIN_H

#include "Accumulator.h"

namespace libzerocoin {

	class ZerocoinParams {
	public:
		const IntegerGroupParams* groupParams;
		const Bignum& accumulatorModulus;
	};

	class PrivateCoin {
	public:
		PrivateCoin(const ZerocoinParams* p, const CBigNum& coinValue);
		void Serialize(Stream& s) const;
		void Unserialize(Stream& s);

	private:
		const ZerocoinParams* params;
		CBigNum value;
	};

}

#endif // ZEROCOIN_H
