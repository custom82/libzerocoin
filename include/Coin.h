#ifndef COIN_H
#define COIN_H

#include "zerocoin_defs.h"

namespace libzerocoin {

	class PublicCoin {
	private:
		const ZerocoinParams* params;
		Bignum value;
		CoinDenomination denomination;

	public:
		PublicCoin(const ZerocoinParams* p, const CBigNum& coin);
		PublicCoin(const ZerocoinParams* p, const CBigNum& coin, const CoinDenomination d);

		bool validate() const;

		const Bignum& getValue() const { return value; }
		CoinDenomination getDenomination() const { return denomination; }
	};

} // namespace libzerocoin

#endif
