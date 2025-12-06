#ifndef ACCUMULATORPROOF_H
#define ACCUMULATORPROOF_H

#include "AccumulatorWitness.h"
#include "Stream.h"
#include "Accumulator.h"

namespace libzerocoin {

	class AccumulatorProofOfKnowledge {
	public:
		AccumulatorProofOfKnowledge(const AccumulatorAndProofParams* params, const Commitment& coin, const uint256 msghash, Accumulator& accumulator);
		void Serialize(Stream& s) const;
		void Unserialize(Stream& s);

	private:
		Bignum C_e;
		Bignum C_u;
		Bignum C_r;
		Bignum st_1;
		Bignum st_2;
		Bignum st_3;
		Bignum t_1;
		Bignum t_2;
		Bignum t_3;
		Bignum t_4;
		Bignum s_alpha;
		Bignum s_beta;
		Bignum s_zeta;
		Bignum s_sigma;
		Bignum s_eta;
	};
}

#endif // ACCUMULATORPROOF_H
