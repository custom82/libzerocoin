#ifndef ACCUMULATOR_PROOF_OF_KNOWLEDGE_H
#define ACCUMULATOR_PROOF_OF_KNOWLEDGE_H

#include "AccumulatorWitness.h" // Aggiunto include per AccumulatorWitness

class AccumulatorProofOfKnowledge {
public:
	void Serialize(Stream& s) const;
	void Unserialize(Stream& s);
};

#endif // ACCUMULATOR_PROOF_OF_KNOWLEDGE_H
