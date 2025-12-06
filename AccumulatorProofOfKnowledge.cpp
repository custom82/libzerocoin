#include "AccumulatorProofOfKnowledge.h"

namespace libzerocoin {

	AccumulatorProofOfKnowledge::AccumulatorProofOfKnowledge(const AccumulatorAndProofParams* params, const Commitment& coin, const uint256 msghash, Accumulator& accumulator) {
		// Inizializzazione del proof
		C_e = Bignum::randBignum(params->accumulatorModulus);
		C_u = Bignum::randBignum(params->accumulatorModulus);
		C_r = Bignum::randBignum(params->accumulatorModulus);
		st_1 = Bignum::randBignum(params->accumulatorModulus);
		st_2 = Bignum::randBignum(params->accumulatorModulus);
		st_3 = Bignum::randBignum(params->accumulatorModulus);
		t_1 = Bignum::randBignum(params->accumulatorModulus);
		t_2 = Bignum::randBignum(params->accumulatorModulus);
		t_3 = Bignum::randBignum(params->accumulatorModulus);
		t_4 = Bignum::randBignum(params->accumulatorModulus);
		s_alpha = Bignum::randBignum(params->accumulatorModulus);
		s_beta = Bignum::randBignum(params->accumulatorModulus);
		s_zeta = Bignum::randBignum(params->accumulatorModulus);
		s_sigma = Bignum::randBignum(params->accumulatorModulus);
		s_eta = Bignum::randBignum(params->accumulatorModulus);
	}

	void AccumulatorProofOfKnowledge::Serialize(Stream& s) const {
		s << C_e << C_u << C_r << st_1 << st_2 << st_3 << t_1 << t_2 << t_3 << t_4 << s_alpha << s_beta << s_zeta << s_sigma << s_eta;
	}

	void AccumulatorProofOfKnowledge::Unserialize(Stream& s) {
		s >> C_e >> C_u >> C_r >> st_1 >> st_2 >> st_3 >> t_1 >> t_2 >> t_3 >> t_4 >> s_alpha >> s_beta >> s_zeta >> s_sigma >> s_eta;
	}

}
