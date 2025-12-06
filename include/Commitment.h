#ifndef COMMITMENT_H
#define COMMITMENT_H

#include "zerocoin_defs.h"

namespace libzerocoin {

	class Commitment {
	private:
		const IntegerGroupParams* params;
		CBigNum contents;

	public:
		Commitment(const IntegerGroupParams* p, const CBigNum& value);

		const CBigNum& getContents() const { return contents; }
		const IntegerGroupParams* getParams() const { return params; }
	};

	class CommitmentProofOfKnowledge {
	private:
		CBigNum C_e;
		CBigNum C_u;
		CBigNum C_r;

	public:
		CommitmentProofOfKnowledge() {}
		CommitmentProofOfKnowledge(const IntegerGroupParams* params, const Commitment& commitment);

		// Getters
		const CBigNum& getC_e() const { return C_e; }
		const CBigNum& getC_u() const { return C_u; }
		const CBigNum& getC_r() const { return C_r; }
	};

} // namespace libzerocoin

#endif
