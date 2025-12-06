#ifndef ZEROCOIN_H
#define ZEROCOIN_H

#include "zerocoin_defs.h"

namespace libzerocoin {

    class PrivateCoin {
    private:
        const ZerocoinParams* params;
        Bignum serialNumber;
        Bignum randomness;
        unsigned char ecdsaSecretKey[32];

    public:
        PrivateCoin(const ZerocoinParams* p, const CBigNum& coinValue);

        const PublicCoin& getPublicCoin() const;
        const Bignum& getSerialNumber() const;
        const Bignum& getRandomness() const;
        const unsigned char* getEcdsaSecretKey() const;
    };

} // namespace libzerocoin

#endif
