#include "Commitment.h"

namespace libzerocoin {

	Commitment::Commitment(const IntegerGroupParams* p, const CBigNum& value)
	: params(p), contents(value) {
	}

	CommitmentProofOfKnowledge::CommitmentProofOfKnowledge(const IntegerGroupParams* params,
														   const Commitment& commitment) {
		(void)params;
		(void)commitment;
		// Stub values
		C_e = CBigNum(1);
		C_u = CBigNum(2);
		C_r = CBigNum(3);
														   }

} // namespace libzerocoin
