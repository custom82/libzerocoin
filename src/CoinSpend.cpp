#include "CoinSpend.h"

namespace libzerocoin {

	CoinSpend::CoinSpend(const ZerocoinParams* p, const PrivateCoin& coin,
						 Accumulator& a, uint32_t checksum)
	: params(p),
	coinSerial(coin.getSerialNumber()),
	accumulatorCommitment(a.getValue()),
	checksum(checksum),
	accumulatorProofOfKnowledge(nullptr),
	serialNumberSignatureOfKnowledge(nullptr) {
		// Stub implementation
	}

	bool CoinSpend::Verify(const Accumulator& accumulator, const SpendMetaData& metaData) const {
		// Stub implementation
		(void)accumulator;
		(void)metaData;
		return true;
	}

	CoinSpend* CoinSpend::Create(const ZerocoinParams* params, const PrivateCoin& coin,
								 Accumulator& accumulator, uint32_t checksum) {
		return new CoinSpend(params, coin, accumulator, checksum);
								 }

} // namespace libzerocoin
