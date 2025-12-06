#ifndef COIN_SPEND_H
#define COIN_SPEND_H

#include "zerocoin_defs.h"
#include <cstdint>
#include <memory>

namespace libzerocoin {

	// Forward declarations
	class AccumulatorProofOfKnowledge;
	class SerialNumberSignatureOfKnowledge;

	class Accumulator {
	public:
		Bignum getValue() const { return Bignum(0); }
	};

	class PrivateCoin {
	public:
		PrivateCoin(const ZerocoinParams* p, const Bignum& coinValue) {}
		const Bignum& getSerialNumber() const { static Bignum b; return b; }
	};

	class SpendMetaData {
	public:
		SpendMetaData() {}
	};

	class CoinSpend {
	private:
		const ZerocoinParams* params;
		Bignum coinSerial;
		Bignum accumulatorCommitment;
		uint32_t checksum;
		std::unique_ptr<AccumulatorProofOfKnowledge> accumulatorProofOfKnowledge;
		std::unique_ptr<SerialNumberSignatureOfKnowledge> serialNumberSignatureOfKnowledge;

	public:
		// Usa riferimenti invece di puntatori (come nel .cpp originale)
		CoinSpend(const ZerocoinParams* p, const PrivateCoin& coin, Accumulator& a, uint32_t checksum);

		template<typename Stream>
		void Serialize(Stream& s) const {}

		template<typename Stream>
		void Unserialize(Stream& s) {}

		bool Verify(const Accumulator& accumulator, const SpendMetaData& metaData) const;

		static CoinSpend* Create(const ZerocoinParams* params, const PrivateCoin& coin,
								 Accumulator& accumulator, uint32_t checksum);
	};

} // namespace libzerocoin

#endif
