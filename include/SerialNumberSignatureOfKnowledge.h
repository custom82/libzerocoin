#ifndef SERIALNUMBER_SIGNATURE_OF_KNOWLEDGE_H
#define SERIALNUMBER_SIGNATURE_OF_KNOWLEDGE_H

#include "zerocoin_defs.h"
#include "serialize_stub.h"

namespace libzerocoin {

	class SerialNumberSignatureOfKnowledge {
	private:
		Bignum s_notprime;
		Bignum sprime;
		uint256 hash;

	public:
		SerialNumberSignatureOfKnowledge();
		SerialNumberSignatureOfKnowledge(const IntegerGroupParams* p);

		bool Verify(const Bignum& coinSerialNumber,
					const Bignum& valueOfCommitmentToCoin,
					const Bignum& serialNumberSokCommitment,
					const uint256& msghash) const;

					// Simple serialization without complex macros
					template<typename Stream>
					void Serialize(Stream& s) const {
						// Stub implementation
					}

					template<typename Stream>
					void Unserialize(Stream& s) {
						// Stub implementation
					}

					// Getters
					const Bignum& getS_notprime() const { return s_notprime; }
					const Bignum& getSprime() const { return sprime; }
					const uint256& getHash() const { return hash; }
	};

} // namespace libzerocoin

#endif
