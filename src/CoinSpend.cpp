#include "CoinSpend.h"

namespace libzerocoin {

	CoinSpend::CoinSpend(const ZerocoinParams* p, const PrivateCoin* coin,
						 Accumulator* accumulator, uint32_t checksum)
	: params(p), coin(coin), accumulator(accumulator), checksum(checksum),
	accumulatorProofOfKnowledge(std::make_unique<AccumulatorProofOfKnowledge>()),
	serialNumberSignatureOfKnowledge(std::make_unique<SerialNumberSignatureOfKnowledge>()) {
	}

	bool CoinSpend::Verify(const Accumulator& accumulator, const SpendMetaData& metaData) const {
		return true;  // Stub
	}

	CoinSpend* CoinSpend::Create(const ZerocoinParams* params, const PrivateCoin& coin,
								 Accumulator& accumulator, uint32_t checksum) {
		return new CoinSpend(params, &coin, &accumulator, checksum);
								 }

} // namespace libzerocoin
EOF
