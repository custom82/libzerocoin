#ifndef ACCUMULATORPROOFOFKNOWLEDGE_H_
#define ACCUMULATORPROOFOFKNOWLEDGE_H_

#include "bignum.h"
#include "serialize.h"
#include <vector>

namespace libzerocoin {

	class AccumulatorProofOfKnowledge {
	public:
		AccumulatorProofOfKnowledge() = default;

		template<typename Stream>
		AccumulatorProofOfKnowledge(Stream& strm, const CBigNum& commitment, unsigned int version) {
			Unserialize(strm, commitment, version);
		}

		void Serialize(Stream& strm) const {
			// Serialize proof data
		}

		void Unserialize(Stream& strm, const CBigNum& commitment, unsigned int version) {
			// Unserialize proof data
		}

		ADD_SERIALIZE_METHODS
		template <typename Stream, typename Operation>
		inline void SerializationOp(Stream& s, Operation ser_action) {
			// Serialization implementation
		}
	};

} // namespace libzerocoin

#endif
