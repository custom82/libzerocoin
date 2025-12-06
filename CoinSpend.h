#ifndef COINSPEND_H
#define COINSPEND_H

#include "Zerocoin.h"
#include "Accumulator.h"
#include "AccumulatorProofOfKnowledge.h"
#include "Commitment.h"

namespace libzerocoin {

	class CoinSpend {
	public:
		CoinSpend(const ZerocoinParams* p, const PrivateCoin& coin, Accumulator& accumulator, uint32_t checksum);
		void Serialize(Stream& s) const;
		void Unserialize(Stream& s);

		bool Verify(const Accumulator& accumulator, const SpendMetaData& metaData) const;
		static CoinSpend* Create(const ZerocoinParams* params, const PrivateCoin& coin, Accumulator& accumulator, uint32_t checksum);

	private:
		const ZerocoinParams* params;
		PrivateCoin coin;
		Accumulator accumulator;
		uint32_t checksum;
		AccumulatorProofOfKnowledge accumulatorProofOfKnowledge;
	};

}

#endif // COINSPEND_H
