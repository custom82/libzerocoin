#ifndef COIN_SPEND_H
#define COIN_SPEND_H

#include "zerocoin_defs.h"
#include <cstdint>

namespace libzerocoin {

	class AccumulatorProofOfKnowledge;
	class SerialNumberSignatureOfKnowledge;

	class CoinSpend {
	private:
		const ZerocoinParams* params;
		const PrivateCoin& coin;
		Accumulator& accumulator;
		uint32_t checksum;
		AccumulatorProofOfKnowledge accumulatorProofOfKnowledge;
		SerialNumberSignatureOfKnowledge serialNumberSignatureOfKnowledge;

	public:
		CoinSpend(const ZerocoinParams* p, const PrivateCoin& coin, Accumulator& a, const uint32_t checksum);

		// Serializzazione
		template<typename Stream>
		void Serialize(Stream& s) const;

		template<typename Stream>
		void Unserialize(Stream& s);

		// Verifica
		bool Verify(const Accumulator& accumulator, const SpendMetaData& metaData) const;

		// Factory method
		static CoinSpend* Create(const ZerocoinParams* params, const PrivateCoin& coin,
								 Accumulator& accumulator, uint32_t checksum);
	};

} // namespace libzerocoin

#endif
