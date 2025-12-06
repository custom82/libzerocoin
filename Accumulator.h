#ifndef ACCUMULATOR_H
#define ACCUMULATOR_H

#include "bitcoin_bignum/bignum.h"
#include "Coin.h"
#include "Params.h"
#include "src/serialize_stub.h"

namespace libzerocoin {

	class Accumulator {
	private:
		const AccumulatorAndProofParams* params;
		CBigNum value;
		CoinDenomination denom;

	public:
		Accumulator(const AccumulatorAndProofParams* p,
					CoinDenomination d = ZQ_LOVELACE)
		: params(p), denom(d)
		{
			value.setuint64(1);
		}

		Accumulator(const ZerocoinParams* p,
					CoinDenomination d = ZQ_LOVELACE)
		: params(&p->accumulatorParams), denom(d)
		{
			value.setuint64(1);
		}

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
	};

	class AccumulatorWitness {
	private:
		const AccumulatorAndProofParams* params;
		const PublicCoin element;
		CBigNum witnessValue;

	public:
		AccumulatorWitness(const ZerocoinParams* p,
						   const Accumulator& checkpoint,
					 const PublicCoin& coin)
		: params(&p->accumulatorParams),
		element(coin),
		witnessValue(checkpoint.getValue())
		{}

		void AddElement(const PublicCoin& c)
		{
			witnessValue = witnessValue.mul_mod(c.value,
												params->accumulatorModulus);
		}

		const CBigNum& getValue() const { return witnessValue; }
	};

}

#endif
