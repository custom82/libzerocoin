#include "CoinSpend.h"
#include "AccumulatorProofOfKnowledge.h"
#include "SerialNumberSignatureOfKnowledge.h"
#include "Zerocoin.h"
#include <stdexcept>

namespace libzerocoin {

	CoinSpend::CoinSpend(const ZerocoinParams* p, const PrivateCoin& coin,
						 Accumulator& accumulator, uint32_t checksum)
	: params(p), coin(coin), accumulator(accumulator), checksum(checksum) {
		// Implementazione stub
		// In una implementazione reale qui si creerebbero le prove
	}

	template<typename Stream>
	void CoinSpend::Serialize(Stream& s) const {
		// Stub
	}

	template<typename Stream>
	void CoinSpend::Unserialize(Stream& s) {
		// Stub
	}

	bool CoinSpend::Verify(const Accumulator& accumulator, const SpendMetaData& metaData) const {
		// Stub - sempre vero per ora
		return true;
	}

	CoinSpend* CoinSpend::Create(const ZerocoinParams* params, const PrivateCoin& coin,
								 Accumulator& accumulator, uint32_t checksum) {
		return new CoinSpend(params, coin, accumulator, checksum);
								 }

} // namespace libzerocoin

