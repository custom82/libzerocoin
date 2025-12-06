#include "ParamGeneration.h"
#include "bitcoin_bignum/hash.h" // FIX per CHashWriter

using namespace libzerocoin;

// Default seed generator bits count:
static const uint32_t SEED_BITS = 256;

// Fix alla firma (dichiara default params)
CBigNum GenerateRandomPrime(uint32_t primeBitLen, const uint256& inSeed,
							uint256* outSeed, unsigned int* outCounter);

CBigNum GenerateRandomPrime(uint32_t primeBitLen, const uint256& inSeed,
							uint256* outSeed = nullptr,
							unsigned int* outCounter = nullptr);

// Implementazione reale… lasciata come in repo
// Se vuoi posso darti anche questa versione ripulita


uint256 CalculateSeed(const CBigNum& modulus, const std::string& label,
					  uint32_t index, std::string debug = "")
{
	std::vector<unsigned char> modBytes = modulus.getvch();

	CHashWriter hasher(0, 0);
	hasher.write((const char*)modBytes.data(), modBytes.size());
	hasher.write(label.data(), label.size());
	hasher.write((const char*)&index, sizeof(index));

	return hasher.GetHash();
}

// … resto del file originale invariato …
