#include "Commitment.h"

namespace libzerocoin {

	Commitment::Commitment(const IntegerGroupParams* p, const CBigNum& value) {
		this->params = p;
		this->value = value;
	}

	void Commitment::Serialize(Stream& s) const {
		s << params << value;
	}

	void Commitment::Unserialize(Stream& s) {
		s >> params >> value;
	}

	CommitmentProofOfKnowledge::CommitmentProofOfKnowledge(const IntegerGroupParams* params, const Commitment& commitment) {
		this->commitment = commitment;
		C_e = Bignum::randBignum(params->groupModulus);
		C_u = Bignum::randBignum(params->groupModulus);
		C_r = Bignum::randBignum(params->groupModulus);
	}

	void CommitmentProofOfKnowledge::Serialize(Stream& s) const {
		s << commitment << C_e << C_u << C_r;
	}

	void CommitmentProofOfKnowledge::Unserialize(Stream& s) {
		s >> commitment >> C_e >> C_u >> C_r;
	}

}
