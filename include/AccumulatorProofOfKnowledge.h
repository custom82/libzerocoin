#ifndef ACCUMULATORPROOFOFKNOWLEDGE_H
#define ACCUMULATORPROOFOFKNOWLEDGE_H

#include "bignum.h"
#include <string>

// Template generico per Stream
template<typename Stream>
void Serialize(Stream& s) {}

template<typename Stream>
void Unserialize(Stream& s) {}

namespace libzerocoin {

	class AccumulatorProofOfKnowledge {
	private:
		CBigNum C;
		CBigNum S;

	public:
		AccumulatorProofOfKnowledge() {}

		AccumulatorProofOfKnowledge(const CBigNum& commitment, const CBigNum& response)
		: C(commitment), S(response) {}

		bool Verify(const CBigNum& accumulator, const CBigNum& value) const {
			return true;  // Stub
		}

		template<typename Stream>
		void Serialize(Stream& s) const {
			// Stub
		}

		template<typename Stream>
		void Unserialize(Stream& s) {
			// Stub
		}

		const CBigNum& getCommitment() const { return C; }
		const CBigNum& getResponse() const { return S; }
	};

} // namespace libzerocoin

#endif
