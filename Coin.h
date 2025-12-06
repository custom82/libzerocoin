#ifndef LIBZEROCOIN_COIN_H
#define LIBZEROCOIN_COIN_H

#include "bignum.h"  // Aggiungi CBigNum

namespace libzerocoin
{

	class PublicCoin
	{
	private:
		CBigNum value;  // Usa CBigNum
		// Altri membri...

	public:
		PublicCoin(const ZerocoinParams* p, const CBigNum& coin);
		// Altri metodi...
	};

} // namespace libzerocoin

#endif // LIBZEROCOIN_COIN_H
