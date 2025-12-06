#ifndef ACCUMULATORWITNESS_H
#define ACCUMULATORWITNESS_H

#include "bignum.h"
#include <string>

class CAccumulatorWitness {
private:
    CBigNum witness_data;

public:
    CAccumulatorWitness() : witness_data(0) {}

    void generateWitness(const CBigNum& accumulator, const CBigNum& value) {
        witness_data = accumulator - value;
    }

    bool verifyWitness(const CBigNum& accumulator, const CBigNum& value) const {
        CBigNum computedWitness = accumulator - value;
        return (computedWitness == witness_data);
    }

    std::string getWitnessDataHex() const {
        return witness_data.GetHex();  // Corretto: GetHex non getHex
    }
};

#endif
