#include "zerocoin_types.h"

namespace libzerocoin {

// IntegerGroupParams
IntegerGroupParams::IntegerGroupParams()
    : g(0), h(0), modulus(0), groupOrder(0) {
}

Bignum IntegerGroupParams::randomElement() const {
    return Bignum::randBignum(modulus);
}

// AccumulatorAndProofParams
AccumulatorAndProofParams::AccumulatorAndProofParams() {
}

// ZerocoinParams
ZerocoinParams::ZerocoinParams(const Bignum& N, uint32_t securityLevel)
    : accumulatorModulus(N), securityLevel(securityLevel) {
}

} // namespace libzerocoin
