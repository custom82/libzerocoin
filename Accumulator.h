#ifndef LIBZEROCOIN_ACCUMULATOR_H
#define LIBZEROCOIN_ACCUMULATOR_H

#include "src/serialize_stub.h"
#include "src/zerocoin_types.h"
#include "bitcoin_bignum/bignum.h"
#include "Params.h"
#include "Coin.h"

namespace libzerocoin {

	class Accumulator
	{
	private:
		const AccumulatorAndProofParams* params;
		CoinDenomination denom;
		CBigNum value;

	public:
		Accumulator(const AccumulatorAndProofParams* p,
					CoinDenomination d = ZQ_LOVELACE)
		: params(p), denom(d), value(1) {}

		Accumulator(const ZerocoinParams* p,
					CoinDenomination d = ZQ_LOVELACE)
		: params(&p->accumulatorParams), denom(d), value(1) {}

		void accumulate(const PublicCoin& c)
		{
			value = value.mul_mod(c.value, params->accumulatorModulus);
		}

		CoinDenomination getDenomination() const { return denom; }

		const CBigNum& getValue() const { return value; }

		Accumulator& operator+=(const PublicCoin& c)
		{
			accumulate(c);
			return *this;
		}

		ADD_SERIALIZE_METHODS;
	};

	class AccumulatorWitness
	{
	private:
		const ZerocoinParams* params;
		PublicCoin element;
		CBigNum witnessValue;

	public:
		AccumulatorWitness(const ZerocoinParams* p,
						   const Accumulator& a,
					 const PublicCoin& coin)
		: params(p), element(coin), witnessValue(a.getValue()) {}

		void AddElement(const PublicCoin& c)
		{
			witnessValue = witnessValue.mul_mod(
				c.value,
				params->accumulatorParams.accumulatorModulus
			);
		}

		const CBigNum& getValue() const { return witnessValue; }

		ADD_SERIALIZE_METHODS;
	};

} // namespace libzerocoin

#endif
