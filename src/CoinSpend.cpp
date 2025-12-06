#include "CoinSpend.h"

namespace libzerocoin {

	CoinSpend::CoinSpend(const ZerocoinParams* p, const PrivateCoin& coin,
						 Accumulator& a, const uint32_t checksum)
	: params(p), coinSerial(coin.getSerialNumber()),
	accumulatorCommitment(a.getValue()), checksum(checksum) {
	}

	bool CoinSpend::Verify(const Accumulator& accumulator, const SpendMetaData& metaData) const {
		// Stub implementation
		(void)accumulator;
		(void)metaData;
		return true;
	}

} // namespace libzerocoin
