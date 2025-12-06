#ifndef LIBZEROCOIN_COIN_H
#define LIBZEROCOIN_COIN_H

#include "src/serialize_stub.h"
#include "src/zerocoin_types.h"

#include "Params.h"
#include "Accumulator.h"
#include "Commitment.h"
#include "bitcoin_bignum/bignum.h"

namespace libzerocoin {

	class PublicCoin
	{
	public:
		CBigNum value;
		CoinDenomination denomination;

		PublicCoin() = default;

		PublicCoin(const ZerocoinParams* p, const CoinDenomination denom, const CBigNum& randomness);

		inline CoinDenomination getDenomination() const { return this->denomination; }

		template <typename Stream, typename Operation>
		inline void SerializationOp(Stream& s, Operation ser_action)
		{
			READWRITE(value);
			READWRITE(denomination);
		}

		ADD_SERIALIZE_METHODS;
	};

	class PrivateCoin
	{
	public:
		PublicCoin publicCoin;
		CBigNum randomness;
		CoinDenomination denomination;
		int version = ZEROCOIN_VERSION;

		PrivateCoin(const ZerocoinParams* p, const CoinDenomination denom, int version = ZEROCOIN_VERSION);

		inline CoinDenomination getDenomination() const { return this->denomination; }

		void mintCoin(const CoinDenomination denom, int version = ZEROCOIN_VERSION);

		ADD_SERIALIZE_METHODS;
	};

} // namespace libzerocoin

#endif
