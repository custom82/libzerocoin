#ifndef LIBZEROCOIN_COMMITMENT_H
#define LIBZEROCOIN_COMMITMENT_H

#include "src/serialize_stub.h"
#include "src/zerocoin_types.h"

#include "bitcoin_bignum/bignum.h"
#include "Params.h"

namespace libzerocoin {

	class Commitment
	{
	private:
		const IntegerGroupParams* params;
		CBigNum commitmentValue;
		CBigNum randomness;
		const CBigNum contents;

	public:
		Commitment(const IntegerGroupParams* p, const CBigNum& value);

		const CBigNum& getCommitmentValue() const { return commitmentValue; }
		const CBigNum& getRandomness() const { return randomness; }
		const CBigNum& getContents() const { return contents; }

		ADD_SERIALIZE_METHODS;
	};

	class CommitmentProofOfKnowledge
	{
	private:
		const IntegerGroupParams* ap;
		const IntegerGroupParams* bp;

		CBigNum S1, S2, S3, challenge;

	public:
		CommitmentProofOfKnowledge(const IntegerGroupParams* aParams,
								   const IntegerGroupParams* bParams,
							 const Commitment& a,
							 const Commitment& b);

		bool Verify(const CBigNum& A, const CBigNum& B) const;

		ADD_SERIALIZE_METHODS;
	};

} // namespace libzerocoin

#endif
