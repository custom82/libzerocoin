#include "AccumulatorProofOfKnowledge.h"

namespace libzerocoin
{

	AccumulatorProofOfKnowledge::AccumulatorProofOfKnowledge(const AccumulatorAndProofParams* params,
															 const Commitment& commitment,
														  const AccumulatorWitness& witness,
														  Accumulator& accumulator)
	{
		// Calcoliamo le variabili qui (ex: C_e, C_u, C_r, ecc)
		C_e = Bignum::randBignum(params->accumulatorModulus);  // Esempio con CBigNum
		// Altri calcoli con CBigNum
	}

	bool AccumulatorProofOfKnowledge::Verify(const Accumulator& accumulator, const CBigNum& valueOfCommitmentToCoin) const
	{
		// Implementiamo la verifica
		return true; // Solo un esempio
	}

	void AccumulatorProofOfKnowledge::Serialize(Stream& s) const
	{
		// Codice di serializzazione
		s << C_e << C_u << C_r << st_1 << st_2 << st_3 << t_1 << t_2 << t_3 << t_4
		<< s_alpha << s_beta << s_zeta << s_sigma << s_eta;
	}

	void AccumulatorProofOfKnowledge::Unserialize(Stream& s)
	{
		// Codice di unserializzazione
		s >> C_e >> C_u >> C_r >> st_1 >> st_2 >> st_3 >> t_1 >> t_2 >> t_3 >> t_4
		>> s_alpha >> s_beta >> s_zeta >> s_sigma >> s_eta;
	}

} // namespace libzerocoin
