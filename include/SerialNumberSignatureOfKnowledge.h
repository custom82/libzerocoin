#ifndef SERIALNUMBERSIGNATUREOFKNOWLEDGE_H_
#define SERIALNUMBERSIGNATUREOFKNOWLEDGE_H_

#include "bignum.h"
#include "serialize.h"

namespace libzerocoin {

	class SerialNumberSignatureOfKnowledge {
	public:
		SerialNumberSignatureOfKnowledge() = default;

		template<typename Stream>
		SerialNumberSignatureOfKnowledge(Stream& strm, const CBigNum& serial, unsigned int version) {
			Unserialize(strm, serial, version);
		}

		void Serialize(Stream& strm) const {
			// Serialize signature data
		}

		void Unserialize(Stream& strm, const CBigNum& serial, unsigned int version) {
			// Unserialize signature data
		}

		ADD_SERIALIZE_METHODS
		template <typename Stream, typename Operation>
		inline void SerializationOp(Stream& s, Operation ser_action) {
			// Serialization implementation
		}
	};

} // namespace libzerocoin

#endif
