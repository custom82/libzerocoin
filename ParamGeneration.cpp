// Copyright (c) 2017 The Zerocoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ParamGeneration.h"
#include "Zerocoin.h"
#include "bitcoin_bignum/bignum.h"
#include <string>
#include <cmath>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/provider.h>  // AGGIUNTO: per OpenSSL 3.x
#include <iostream>

using namespace std;

namespace libzerocoin {

	// AGGIUNTO: Inizializzazione OpenSSL 3.x
	#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	static void init_openssl_3_if_needed() {
		static bool initialized = false;
		if (!initialized) {
			OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
			OSSL_PROVIDER_load(NULL, "legacy");
			initialized = true;
		}
	}
	#endif

	CBigNum generateIntegerFromSeed(uint32_t numBits, arith_uint256& seed, uint8_t* g, uint32_t *count)
	{
		CBigNum result(0);
		uint32_t iterations = (uint32_t)ceil((double)numBits / (double)HASH_OUTPUT_BITS);

		BN_CTX* bn_ctx = BN_CTX_new();
		if (!bn_ctx)
			throw ZerocoinException("CBigNum::generateIntegerFromSeed : BN_CTX_new failed");

		BN_CTX_start(bn_ctx);

		try {
			for (uint32_t i = 0; i < iterations; i++) {
				CSHA256 hasher;
				uint256 hash;

				hasher.Write(seed.begin(), 32);
				hasher.Write(g, 32);
				hasher.Finalize(hash.begin());
				seed = arith_uint256(hash);

				CBigNum hashBN;
				hashBN.setuint256(seed);

				result = result << HASH_OUTPUT_BITS;
				result = result + hashBN;

				if (count)
					(*count)++;
			}

			CBigNum mask = (CBigNum(1) << numBits) - 1;
			result = result & mask;

		} catch (...) {
			BN_CTX_end(bn_ctx);
			BN_CTX_free(bn_ctx);
			throw;
		}

		BN_CTX_end(bn_ctx);
		BN_CTX_free(bn_ctx);
		return result;
	}

	uint256 calculateSeed(Params* params,
						  CBigNum modulus,
					   string auxString,
					   uint32_t index)
	{
		CHashWriter hasher(0,0);
		hasher << *params;
		hasher << modulus;
		hasher << auxString;
		hasher << index;

		uint256 hash = hasher.GetHash();
		return hash;
	}

	uint256 calculateGeneratorSeed(uint256 seed, uint256 pSeed, uint256 qSeed,
								   string label, uint32_t index)
	{
		CHashWriter hasher(0,0);
		hasher << seed;
		hasher << pSeed;
		hasher << qSeed;
		hasher << label;
		hasher << index;

		uint256 hash = hasher.GetHash();
		return hash;
	}

	CBigNum calculateGroupGenerator(uint256 seed, uint256 pSeed, uint256 qSeed,
									CBigNum modulus, CBigNum groupOrder,
									uint32_t index)
	{
		CBigNum result;
		arith_uint256 i = 0;
		while (result.isZero()) {
			arith_uint256 hash = calculateGeneratorSeed(seed, pSeed, qSeed, "J", UintToArith256(i));

			if (i == 0)
				throw ZerocoinException("calculateGroupGenerator: failed to find generator");
			i = i - 1;

			CBigNum candidate(hash);
			candidate = candidate % modulus;

			if (candidate.isOne()) continue;
			if (!candidate.isCoprime(modulus)) continue;
			if (candidate.pow_mod(groupOrder, modulus) != 1) continue;

			result = candidate;
		}

		return result;
	}

	CBigNum generateRandomPrime(uint32_t primeBits)
	{
		CBigNum result;
		bool found = false;

		// AGGIUNTO: Inizializza OpenSSL 3.x
		#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		init_openssl_3_if_needed();
		#endif

		while (!found) {
			unsigned char* buffer = new unsigned char[primeBits/8];

			#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			init_openssl_3_if_needed();
			#endif

			if (RAND_bytes(buffer, primeBits/8) != 1) {
				delete[] buffer;
				throw ZerocoinException("generateRandomPrime: RAND_bytes failed");
			}

			BIGNUM* bn = BN_new();
			BN_bin2bn(buffer, primeBits/8, bn);
			delete[] buffer;

			BN_set_bit(bn, primeBits - 1);

			if (!BN_is_odd(bn))
				BN_add_word(bn, 1);

			CBigNum candidate;
			candidate.setBN(bn);
			BN_free(bn);

			if (candidate.isPrime()) {
				result = candidate;
				found = true;
			}
		}

		return result;
	}

	void calculateGroupModulusAndOrder(arith_uint256 seed, uint32_t pLen, uint32_t qLen,
									   CBigNum *resultModulus, CBigNum *resultGroupOrder,
									   arith_uint256 *resultPseed, arith_uint256 *resultQseed)
	{
		bool found = false;
		uint32_t pTries = 0, qTries = 0;
		CBigNum p, q, n;

		while (!found) {
			arith_uint256 pSeed = seed;
			uint8_t* pSeedBytes = new uint8_t[32];
			memcpy(pSeedBytes, pSeed.begin(), 32);
			p = generateIntegerFromSeed(pLen, pSeed, pSeedBytes, &pTries);
			delete[] pSeedBytes;

			if (!p.isPrime()) {
				continue;
			}

			arith_uint256 qSeed = calculateSeed(NULL, p, "prime", 0);
			uint8_t* qSeedBytes = new uint8_t[32];
			memcpy(qSeedBytes, qSeed.begin(), 32);
			q = generateIntegerFromSeed(qLen, qSeed, qSeedBytes, &qTries);
			delete[] qSeedBytes;

			if (!q.isPrime() || q == p) {
				continue;
			}

			n = p * q;

			if (n.bitSize() == pLen + qLen) {
				*resultModulus = n;
				*resultGroupOrder = (p - 1) * (q - 1);
				*resultPseed = pSeed;
				*resultQseed = qSeed;
				found = true;
			}
		}
	}

	Params* ZerocoinParams::GetTestParams()
	{
		CBigNum g = CBigNum(2);
		CBigNum h = CBigNum(3);

		CBigNum accumulatorModulus;
		accumulatorModulus.SetHex("1234567890ABCDEF");

		CBigNum coinCommitmentModulus;
		coinCommitmentModulus.SetHex("FEDCBA0987654321");

		CBigNum serialNumberSoKCommitmentModulus;
		serialNumberSoKCommitmentModulus.SetHex("AABBCCDDEEFF0011");

		return new Params(accumulatorModulus, coinCommitmentModulus,
						  serialNumberSoKCommitmentModulus, g, h);
	}

} // namespace libzerocoin
