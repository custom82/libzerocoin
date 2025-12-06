// Copyright (c) 2017-2022 The Phore developers
// Copyright (c) 2017-2022 The Phoq developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef COINSPEND_H
#define COINSPEND_H

#include "Accumulator.h"
#include "AccumulatorProofOfKnowledge.h"
#include "Coin.h"
#include "Commitment.h"
#include "Params.h"
#include "SerialNumberSignatureOfKnowledge.h"
#include "SpendMetaData.h"
#include "bitcoin_bignum/bignum.h"

// OpenSSL 3.5 compatibility
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

namespace libzerocoin {

	/** The complete proof needed to spend a zerocoin.
	 */
	class CoinSpend {
	public:
		CoinSpend(){};

		/** Creates a coin spend proof of a public coin
		 *
		 * @param p zerocoin params
		 * @param coin the public coin to spend
		 * @param a the accumulator containing the coin
		 * @param checksum the checksum of the accumulator
		 * @param accumulatorPoK proof of knowledge of the accumulator
		 * @param serialNumberSoK signature of knowledge of the serial number
		 * @param newAccumulator the new accumulator after the spend
		 * @param newChecksum the new checksum after the spend
		 * @param commitment the commitment to the serial number and randomness
		 * @param denomination the denomination of the coin
		 */
		CoinSpend(const ZerocoinParams* p, const PublicCoin& coin, Accumulator& a, const uint32_t checksum,
				  const AccumulatorProofOfKnowledge& accumulatorPoK, const SerialNumberSignatureOfKnowledge& serialNumberSoK,
			const AccumulatorWitness& witness, const uint32_t& newAccumulator, const CBigNum& newChecksum,
			const Commitment& commitment, const CoinDenomination d);

		/** Creates a coin spend proof of a private coin
		 *
		 * @param p zerocoin params
		 * @param coin the private coin to spend
		 * @param a the accumulator containing the coin
		 * @param checksum the checksum of the accumulator
		 * @param msghash hash of the transaction
		 * @param metadat the spend metadata
		 */
		CoinSpend(const ZerocoinParams* p, const PrivateCoin& coin, Accumulator& a, const uint32_t checksum,
				  const uint256& msghash, const SpendMetaData& metadata);

		CoinSpend(const ZerocoinParams* p, const PrivateCoin& coin, Accumulator& a, const uint32_t checksum,
				  const SpendMetaData& m);

		CoinSpend(const ZerocoinParams* p, const PrivateCoin& coin, Accumulator& a, const uint32_t checksum);

		virtual ~CoinSpend(){};

		const CBigNum& getCoinSerialNumber() const { return this->coinSerialNumber; }
		const uint256 getTxHash() const { return ptxHash; }
		void setTxHash(uint256 txHash) { ptxHash = txHash; }

		const CoinDenomination getDenomination() const { return this->denomination; }
		int64_t getDenominationAsAmount() const { return ZerocoinDenominationToAmount(this->denomination); }

		// Returns true if the proof is valid for the given coin, accumulator, and checksum
		bool Verify(const Accumulator& a, const uint32_t checksum) const;
		bool HasValidSerial(ZerocoinParams* params) const;
		bool HasValidSignature() const;
		CBigNum CalculateValidSerial(ZerocoinParams* params);

		void setVersion(int nVersion) { this->version = nVersion; }
		int getVersion() const { return this->version; }

		const SpendMetaData getMetaData() const { return this->metadata; }

		// Setters for use in testing
		void setAccumulatorBlockHash(const uint256& hash) { this->accumulatorBlockHash = hash; }
		void setDenomination(CoinDenomination denom) { this->denomination = denom; }

		ADD_SERIALIZE_METHODS;
		template <typename Stream, typename Operation>
		inline void SerializationOp(Stream& s, Operation ser_action) {
			READWRITE(version);
			READWRITE(coinSerialNumber);
			READWRITE(randomness);
			READWRITE(serialCommitmentToCoinValue);
			READWRITE(accumulatorCommitmentToCoinValue);
			READWRITE(coinValue);
			READWRITE(accumulatorPoK);
			READWRITE(serialNumberSoK);
			READWRITE(commitmentPoK);
			READWRITE(denomination);
			READWRITE(ptxHash);

			// Only serialize accumulatorBlockHash for V3+ spends
			if (version >= 3) {
				READWRITE(accumulatorBlockHash);
			}

			// Only serialize accumulatorId for V4+ spends
			if (version >= 4) {
				READWRITE(accumulatorId);
			}
		}

		static CoinSpend* Create(const ZerocoinParams* paramsZerocoin, const PrivateCoin& coin,
								 Accumulator& accumulator, const uint32_t checksum,
								 const SpendMetaData& metadata, const uint256& msghash);

		static std::vector<unsigned char> ParseCoinSpend(const CDataStream& data);

	protected:
		int version;
		uint256 ptxHash{};
		CBigNum coinSerialNumber;
		CBigNum randomness;
		CBigNum serialCommitmentToCoinValue;
		CBigNum accumulatorCommitmentToCoinValue;
		CoinDenomination denomination;
		uint256 accumulatorBlockHash;
		uint32_t accumulatorId{0};

		// The following fields are only used in v3+ spends
		CBigNum coinValue;
		AccumulatorProofOfKnowledge accumulatorPoK;
		SerialNumberSignatureOfKnowledge serialNumberSoK;
		CommitmentProofOfKnowledge commitmentPoK;

		SpendMetaData metadata;

		// Returns the serial number of the coin
		const CBigNum calculateSerial(const ZerocoinParams* params);
		// Returns the randomness of the coin
		const CBigNum calculateRandomness();

		// Returns the hash of the signature meta data
		const CBigNum signatureHash() const;
	};

} /* namespace libzerocoin */

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#endif /* COINSPEND_H */
