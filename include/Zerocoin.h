#ifndef ZEROCOIN_H
#define ZEROCOIN_H

#include "zerocoin_defs.h"

namespace libzerocoin {

class PrivateCoin {
public:
    PrivateCoin(const ZerocoinParams* p, const CBigNum& coinValue);

    const PublicCoin& getPublicCoin() const;
    const CBigNum& getSerialNumber() const;
    const CBigNum& getRandomness() const;
    const unsigned char* getEcdsaSecretKey() const;

private:
    const ZerocoinParams* params;
    CBigNum serialNumber;
    CBigNum randomness;
    unsigned char ecdsaSecretKey[32];
};

} // namespace libzerocoin

#endif
