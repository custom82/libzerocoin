#include "Zerocoin.h"
#include <openssl/rand.h>

namespace libzerocoin {

PrivateCoin::PrivateCoin(const ZerocoinParams* p, const CBigNum& coinValue)
    : params(p) {
    // Genera numeri casuali (stub)
    unsigned char buffer[32];
    RAND_bytes(buffer, sizeof(buffer));
    serialNumber.setvch(std::vector<unsigned char>(buffer, buffer + 32));

    RAND_bytes(buffer, sizeof(buffer));
    randomness.setvch(std::vector<unsigned char>(buffer, buffer + 32));

    RAND_bytes(ecdsaSecretKey, sizeof(ecdsaSecretKey));
}

const PublicCoin& PrivateCoin::getPublicCoin() const {
    static PublicCoin stub(nullptr, CBigNum(0));
    return stub;
}

const CBigNum& PrivateCoin::getSerialNumber() const {
    return serialNumber;
}

const CBigNum& PrivateCoin::getRandomness() const {
    return randomness;
}

const unsigned char* PrivateCoin::getEcdsaSecretKey() const {
    return ecdsaSecretKey;
}

} // namespace libzerocoin

