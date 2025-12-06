#ifndef LIBZEROCOIN_ACCUMULATORPROOF_H
#define LIBZEROCOIN_ACCUMULATORPROOF_H

#include "bignum.h"  // Aggiungi CBigNum
#include "Commitment.h"
#include "Accumulator.h"
#include "Coin.h"
#include "AccumulatorWitness.h"  // Aggiungi questo include
#include "stream.h"  // Aggiungi questo include per Stream

namespace libzerocoin
{

	class AccumulatorProofOfKnowledge
	{
	private:
		CBigNum C_e;
		CBigNum C_u;
		CBigNum C_r;
		CBigNum st_1;
		CBigNum st_2;
		CBigNum st_3;
		CBigNum t_1;
		CBigNum t_2;
		CBigNum t_3;
		CBigNum t_4;
		CBigNum s_alpha;
		CBigNum s_beta;
		CBigNum s_zeta;
		CBigNum s_sigma;
		CBigNum s_eta;

	public:
		AccumulatorProofOfKnowledge(const AccumulatorAndProofParams* params,
									const Commitment& commitment,
							  const AccumulatorWitness& witness,
							  Accumulator& accumulator);

		bool Verify(const Accumulator& accumulator, const CBigNum& valueOfCommitmentToCoin) const;

		void Serialize(Stream& s) const;
		void Unserialize(Stream& s);

		IMPLEMENT_SERIALIZE(
			READWRITE(C_e);
