#ifndef COINSPEND_H
#define COINSPEND_H

#include <memory>
#include <vector>
#include "Coin.h"
#include "Commitment.h"
#include "Accumulator.h"
#include "AccumulatorProofOfKnowledge.h"
#include "SerialNumberSignatureOfKnowledge.h"
#include "bignum.h"
#include "hash.h"
#include "zerocoin_defs.h"

namespace libzerocoin {

	// Forward declarations
	class ZerocoinParams;

	class CoinSpend {
	public:
		CoinSpend() = default;
		CoinSpend(const ZerocoinParams* params, const PrivateCoin& coin,
				  Accumulator& a, const uint32_t& checksum,
			const AccumulatorWitness& witness, const uint256& ptxHash);
		~CoinSpend() = default;

		const CBigNum& getCoinSerialNumber() const { return this->coinSerialNumber; }
		const uint256 getTxOutHash() const { return ptxHash; }
		const uint32_t getAccumulatorChecksum() const { return this->accChecksum; }
		const CoinDenomination getDenomination() const { return this->denomination; }
		const unsigned char getVersion() const { return version; }
		bool HasValidSerial(ZerocoinParams* params) const;

		// Serialization
		template<typename Stream>
		void Serialize(Stream& s) const;

		template<typename Stream>
		void Unserialize(Stream& s);

	private:
		CoinDenomination denomination = ZQ_ERROR;
		uint32_t accChecksum = 0;
		CBigNum coinSerialNumber;
		CBigNum accumulatorCommitment;
		std::unique_ptr<AccumulatorProofOfKnowledge> accumulatorProofOfKnowledge;
		std::unique_ptr<SerialNumberSignatureOfKnowledge> serialNumberSignatureOfKnowledge;
		uint256 ptxHash;
		unsigned char version = 0;
		uint8_t bytes[192];
		int32_t txVersion = 1;
	};

} // namespace libzerocoin

#endif // COINSPEND_H
