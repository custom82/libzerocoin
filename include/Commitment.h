#ifndef COMMITMENT_H
#define COMMITMENT_H

#include "bignum.h"
#include "Stream.h"
#include "CommitmentProofOfKnowledge.h"
#include "Accumulator.h"
#include "Zerocoin.h"

namespace libzerocoin {

	class Commitment {
	public:
		Commitment(const IntegerGroupParams* p, const CBigNum& value);
		void Serialize(Stream& s) const;
		void Unserialize(Stream& s);

	private:
		const IntegerGroupParams* params;
		CBigNum value;
	};

	class CommitmentProofOfKnowledge {
	public:
		CommitmentProofOfKnowledge(const IntegerGroupParams* params, const Commitment& commitment);
		void Serialize(Stream& s) const;
		void Unserialize(Stream& s);

	private:
		Commitment commitment;
		Bignum C_e;
		Bignum C_u;
		Bignum C_r;
	};
}

#endif // COMMITMENT_H
