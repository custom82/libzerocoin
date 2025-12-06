// Copyright (c) 2017-2024 The Zerocoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef COINSPEND_H_
#define COINSPEND_H_

#include <memory>
#include <vector>
#include "Coin.h"
#include "Commitment.h"
#include "Params.h"
#include "Accumulator.h"
#include "AccumulatorProofOfKnowledge.h"
#include "SerialNumberSignatureOfKnowledge.h"
#include "bignum.h"
#include "hash.h"

namespace libzerocoin {

	class AccumulatorProofOfKnowledge;
	class SerialNumberSignatureOfKnowledge;

	class CoinSpend {
	public:
		CoinSpend() {}
		CoinSpend(const ZerocoinParams* params, const PrivateCoin& coin,
				  Accumulator& a, const uint32_t& checksum,
			const AccumulatorWitness& witness, const uint256& ptxHash);
		CoinSpend(const ZerocoinParams* params,
				  const PrivateCoin& coin,
			const uint32_t checksum,
			const Accumulator& accumulator,
			const uint256& ptxHash,
			const std::vector<std::vector<unsigned char>>& vBoundParams = std::vector<std::vector<unsigned char>>());

		virtual ~CoinSpend();

		const CBigNum& getCoinSerialNumber() const { return this->coinSerialNumber; }
		const uint256 getTxOutHash() const { return ptxHash; }
		const CBigNum& getAccumulatorCommitment() const { return accumulatorCommitment; }
		const uint32_t getAccumulatorChecksum() const { return this->accChecksum; }
		const AccumulatorProofOfKnowledge* getAccumulatorProofOfKnowledge() const {
			return accumulatorProofOfKnowledge.get();
		}
		const SerialNumberSignatureOfKnowledge* getSerialNumberSignatureOfKnowledge() const {
			return serialNumberSignatureOfKnowledge.get();
		}
		const CoinDenomination getDenomination() const { return this->denomination; }
		const unsigned char getVersion() const { return version; }
		bool HasValidSerial(ZerocoinParams* params) const;
		bool HasValidSignature() const;
		CBigNum CalculateValidSerial(ZerocoinParams* params);
		const uint8_t* getCharBytes() const { return bytes; }
		int32_t getTransactionVersion() const { return this->txVersion; }
		void setTxOutHash(uint256 txOutHash) { this->ptxHash = txOutHash; }
		void setVersion(unsigned char version) { this->version = version; }

		ADD_SERIALIZE_METHODS
		template <typename Stream, typename Operation>
		inline void SerializationOp(Stream& s, Operation ser_action) {
			READWRITE(version);
			READWRITE(denomination);
			READWRITE(ptxHash);
			READWRITE(accChecksum);
			READWRITE(coinSerialNumber);
			READWRITE(accumulatorCommitment);

			if (ser_action.ForRead()) {
				accumulatorProofOfKnowledge.reset(new AccumulatorProofOfKnowledge(s, accumulatorCommitment, version));
				serialNumberSignatureOfKnowledge.reset(new SerialNumberSignatureOfKnowledge(s, coinSerialNumber, version));
			} else {
				if (accumulatorProofOfKnowledge)
					accumulatorProofOfKnowledge->Serialize(s);
				if (serialNumberSignatureOfKnowledge)
					serialNumberSignatureOfKnowledge->Serialize(s);
			}
		}

	protected:
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

	private:
		CoinSpend(const ZerocoinParams* params);
	};

} /* namespace libzerocoin */
#endif /* COINSPEND_H_ */
