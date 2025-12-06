#ifndef LIBZEROCOIN_ACCUMULATORPROOF_H
#define LIBZEROCOIN_ACCUMULATORPROOF_H

#include <vector>
#include "bignum.h"  // Include il file dove è definito CBigNum
#include "Commitment.h"
#include "Accumulator.h"
#include "Coin.h"

namespace libzerocoin
{

	// Dichiariamo l'uso di CBigNum al posto di Bignum
	class AccumulatorProofOfKnowledge
	{
	private:
		CBigNum C_e; // CBigNum invece di Bignum
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
		// Constructor per inizializzare i membri
		AccumulatorProofOfKnowledge(const AccumulatorAndProofParams* params, const Commitment& commitment,
									const AccumulatorWitness& witness, Accumulator& accumulator);

		bool Verify(const Accumulator& accumulator, const CBigNum& valueOfCommitmentToCoin) const;

		void Serialize(Stream& s) const;
		void Unserialize(Stream& s);

		IMPLEMENT_SERIALIZE(
			READWRITE(C_e);
			READWRITE(C_u);
			READWRITE(C_r);
			READWRITE(st_1);
			READWRITE(st_2);
			READWRITE(st_3);
			READWRITE(t_1);
			READWRITE(t_2);
			READWRITE(t_3);
			READWRITE(t_4);
			READWRITE(s_alpha);
			READWRITE(s_beta);
			READWRITE(s_zeta);
			READWRITE(s_sigma);
			READWRITE(s_eta);
		)
	};

} // namespace libzerocoin

#endif // LIBZEROCOIN_ACCUMULATORPROOF_H
