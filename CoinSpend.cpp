#include "CoinSpend.h"

namespace libzerocoin {

	CoinSpend::CoinSpend(const ZerocoinParams* p, const PrivateCoin& coin, Accumulator& accumulator, uint32_t checksum)
	: params(p), coin(coin), accumulator(accumulator), checksum(checksum) {
		// Initialize the accumulator proof of knowledge
		accumulatorProofOfKnowledge = AccumulatorProofOfKnowledge(params, coin, checksum, accumulator);
	}

	void CoinSpend::Serialize(Stream& s) const {
		s << coin << accumulator << checksum << accumulatorProofOfKnowledge;
	}

	void CoinSpend::Unserialize(Stream& s) {
		s >> coin >> accumulator >> checksum >> accumulatorProofOfKnowledge;
	}

	bool CoinSpend::Verify(const Accumulator& accumulator, const SpendMetaData& metaData) const {
		// Verify the CoinSpend logic here
		return accumulatorProofOfKnowledge.Verify(accumulator, metaData);
	}

	CoinSpend* CoinSpend::Create(const ZerocoinParams* params, const PrivateCoin& coin, Accumulator& accumulator, uint32_t checksum) {
		return new CoinSpend(params, coin, accumulator, checksum);
	}

}
