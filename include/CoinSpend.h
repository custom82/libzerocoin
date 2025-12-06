#ifndef COIN_SPEND_H
#define COIN_SPEND_H

#include "CBigNum.h" // Aggiunto include per CBigNum

class CoinSpend {
public:
	CoinSpend(const ZerocoinParams* p, const PrivateCoin& coin, Accumulator& a, const uint32_t checksum);
};

#endif // COIN_SPEND_H
