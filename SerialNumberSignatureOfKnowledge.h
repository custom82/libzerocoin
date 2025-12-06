// Copyright (c) 2017-2022 The Phore developers
// Copyright (c) 2017-2022 The Phoq developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SERIALNUMBER_SIGNATURE_OF_KNOWLEDGE_H
#define SERIALNUMBER_SIGNATURE_OF_KNOWLEDGE_H

#include "bitcoin_bignum/bignum.h"
#include "bitcoin_bignum/hash.h"
#include "Params.h"
#include "serialize.h"

// OpenSSL 3.5 compatibility
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

namespace libzerocoin {

	/** A Signature of Knowledge on the hash of a commitment to a coin's serial number.
	 */
	class SerialNumberSignatureOfKnowledge {
	public:
		SerialNumberSignatureOfKnowledge(){};
		SerialNumberSignatureOfKnowledge(const ZerocoinParams* p);

		/** Creates a Signature of Knowledge object for a given coin commitment.
		 *
		 * @param p zerocoin params
		 * @param coin the coin commitment
		 * @param msghash hash of the transaction
		 */
		SerialNumberSignatureOfKnowledge(const ZerocoinParams* p, const Commitment& coin, const uint256 msghash);

		virtual ~SerialNumberSignatureOfKnowledge(){};

		/** Verifies the Signature of Knowledge.
		 *
		 * @return true if valid
		 */
		bool Verify(const CBigNum& coinCommitment, const uint256 msghash) const;

		ADD_SERIALIZE_METHODS;
		template <typename Stream, typename Operation>
		inline void SerializationOp(Stream& s, Operation ser_action) {
			READWRITE(s_notprime);
			READWRITE(sprime);
			READWRITE(hash);
		}

	private:
		const ZerocoinParams* params;
		CBigNum s_notprime;
		CBigNum sprime;
		CBigNum hash;

		/** Proves knowledge of a coin's serial number in the commitment.
		 *
		 * @param commitment the commitment to the coin's serial number
		 * @param msghash hash of the transaction
		 */
		void Prove(const Commitment& commitment, const uint256 msghash);
	};

} /* namespace libzerocoin */

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#endif /* SERIALNUMBER_SIGNATURE_OF_KNOWLEDGE_H */
