#include "Coin.h"
#include "Zerocoin.h"
#include <openssl/rand.h>

namespace libzerocoin {

	// PublicCoin implementation
	PublicCoin::PublicCoin(const ZerocoinParams* p, const CBigNum& coin)
	: params(p), value(coin), denomination(ZQ_ONE) {
	}

	PublicCoin::PublicCoin(const ZerocoinParams* p, const CBigNum& coin, const CoinDenomination d)
	: params(p), value(coin), denomination(d) {
	}

	bool PublicCoin::validate() const {
		// Stub validation
		return value > CBigNum(0);
	}

	// PrivateCoin implementation
	PrivateCoin::PrivateCoin(const ZerocoinParams* p, const CBigNum& coinValue)
	: params(p) {
		// Generate random values
		unsigned char buffer[32];

		// Generate serial number
		RAND_bytes(buffer, sizeof(buffer));
		std::vector<unsigned char> serialVec(buffer, buffer + 32);
		serialNumber.setvch(serialVec);

		// Generate randomness
		RAND_bytes(buffer, sizeof(buffer));
		std::vector<unsigned char> randomVec(buffer, buffer + 32);
		randomness.setvch(randomVec);

		// Generate ECDSA secret key
		RAND_bytes(ecdsaSecretKey, sizeof(ecdsaSecretKey));
	}

	const PublicCoin& PrivateCoin::getPublicCoin() const {
		// Create a public coin from this private coin
		static PublicCoin publicCoin(params, CBigNum(1)); // Stub value
		return publicCoin;
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
