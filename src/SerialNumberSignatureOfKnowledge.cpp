#include "SerialNumberSignatureOfKnowledge.h"
#include "serialize_stub.h"

namespace libzerocoin {

	SerialNumberSignatureOfKnowledge::SerialNumberSignatureOfKnowledge() {
	}

	SerialNumberSignatureOfKnowledge::SerialNumberSignatureOfKnowledge(const IntegerGroupParams* p) {
		(void)p;
	}

	bool SerialNumberSignatureOfKnowledge::Verify(const Bignum& coinSerialNumber,
												  const Bignum& valueOfCommitmentToCoin,
												  const Bignum& serialNumberSokCommitment,
												  const uint256& msghash) const {
													  (void)coinSerialNumber;
													  (void)valueOfCommitmentToCoin;
													  (void)serialNumberSokCommitment;
													  (void)msghash;
													  return true; // Stub
												  }

} // namespace libzerocoin
