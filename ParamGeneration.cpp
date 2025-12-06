// Copyright (c) 2017-2022 The Phore developers
// Copyright (c) 2017-2022 The Phoq developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ParamGeneration.h"
#include "hash.h"
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <iostream>
#include <sstream>

// OpenSSL 3.5 compatibility
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

namespace libzerocoin {

	uint256 CalculateSeed(const CBigNum& modulus, const std::string& auxString,
						  uint32_t securityLevel, std::string groupName) {
		CHashWriter hasher(0,0);

		// Convert CBigNum to vector for hashing
		std::vector<unsigned char> modBytes = modulus.getvch();
		hasher.write((const char*)modBytes.data(), modBytes.size());

		hasher.write((const char*)auxString.data(), auxString.size());
		hasher.write((const char*)&securityLevel, sizeof(securityLevel));
		hasher.write((const char*)groupName.data(), groupName.size());

		return hasher.GetHash();
						  }

						  uint256 CalculateGeneratorSeed(const uint256& seed, const CBigNum& modulus,
														 const std::string& groupName, uint32_t index) {
							  CHashWriter hasher(0,0);

							  hasher.write((const char*)&seed, sizeof(seed));

							  // Convert CBigNum to vector for hashing
							  std::vector<unsigned char> modBytes = modulus.getvch();
							  hasher.write((const char*)modBytes.data(), modBytes.size());

							  hasher.write((const char*)groupName.data(), groupName.size());
							  hasher.write((const char*)&index, sizeof(index));

							  return hasher.GetHash();
														 }

														 uint256 CalculateHash(const uint256& input) {
															 CHashWriter hasher(0,0);
															 hasher.write((const char*)&input, sizeof(input));
															 return hasher.GetHash();
														 }

														 CBigNum GenerateRandomPrime(uint32_t primeBitLen, const uint256& inSeed,
																					 uint256 *outSeed, unsigned int *prime_gen_counter) {
															 // Validate input
															 if (primeBitLen < 2) {
																 throw std::runtime_error("Prime bit length must be at least 2 bits");
															 }

															 if (primeBitLen > 10000) {
																 throw std::runtime_error("Prime bit length too large");
															 }

															 // Calculate first seed = SHA256(inputSeed)
															 uint256 firstSeed = CalculateHash(inSeed);

															 // Calculate second seed = SHA256(firstSeed)
															 uint256 secondSeed = CalculateHash(firstSeed);

															 CBigNum prime;
															 bool primeFound = false;
															 unsigned int count = 0;

															 // Set up OpenSSL context
															 CAutoBN_CTX ctx;
															 BN_CTX_start(ctx);

															 try {
																 while (!primeFound) {
																	 // Generate candidate = SHA256(secondSeed || count)
																	 CHashWriter hasher(0,0);
																	 hasher.write((const char*)&secondSeed, sizeof(secondSeed));
																	 hasher.write((const char*)&count, sizeof(count));

																	 uint256 candidateHash = hasher.GetHash();

																	 // Convert hash to bignum
																	 CBigNum candidate;
																	 BN_bin2bn(candidateHash.begin(), 32, candidate.get());

																	 // Set the most significant bit to ensure correct bit length
																	 BN_set_bit(candidate.get(), primeBitLen - 1);

																	 // Set the least significant bit to make it odd
																	 BN_set_bit(candidate.get(), 0);

																	 // Ensure candidate is in range [2^(primeBitLen-1), 2^primeBitLen - 1]
																	 // Clear any bits above primeBitLen
																	 for (unsigned int i = primeBitLen; i < BN_num_bits(candidate.get()); i++) {
																		 BN_clear_bit(candidate.get(), i);
																	 }

																	 // If candidate is less than 2^(primeBitLen-1), add 2^(primeBitLen-1)
																	 CBigNum minValue;
																	 BN_set_bit(minValue.get(), primeBitLen - 1);

																	 if (BN_cmp(candidate.get(), minValue.get()) < 0) {
																		 if (!BN_add(candidate.get(), candidate.get(), minValue.get())) {
																			 throw std::runtime_error("BN_add failed");
																		 }
																	 }

																	 // Ensure it's still odd
																	 BN_set_bit(candidate.get(), 0);

																	 // Simple trial division for small primes first
																	 static const unsigned int smallPrimes[] = {
																		 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
																		 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151
																	 };

																	 bool divisible = false;
																	 for (unsigned int p : smallPrimes) {
																		 if (BN_mod_word(candidate.get(), p) == 0) {
																			 divisible = true;
																			 break;
																		 }
																	 }

																	 if (!divisible) {
																		 // Use OpenSSL's Miller-Rabin primality test
																		 BN_GENCB* cb = BN_GENCB_new();
																		 if (!cb) {
																			 throw std::runtime_error("BN_GENCB_new failed");
																		 }

																		 // Determine number of Miller-Rabin checks based on bit length
																		 int checks = 0;
																		 if (primeBitLen <= 256) checks = 27;
																		 else if (primeBitLen <= 512) checks = 15;
																		 else if (primeBitLen <= 1024) checks = 8;
																		 else if (primeBitLen <= 2048) checks = 4;
																		 else checks = 2;

																		 int is_prime = BN_is_prime_fasttest_ex(candidate.get(), checks, ctx, 1, cb);
																		 BN_GENCB_free(cb);

																		 if (is_prime == 1) {
																			 prime = candidate;
																			 primeFound = true;

																			 if (outSeed) {
																				 *outSeed = firstSeed;
																			 }
																			 if (prime_gen_counter) {
																				 *prime_gen_counter = count;
																			 }

																			 break;
																		 }
																	 }

																	 count++;

																	 // Safety check
																	 if (count > 1000000) {
																		 throw std::runtime_error("Failed to find prime after 1,000,000 iterations");
																	 }
																 }
															 }
															 catch (...) {
																 BN_CTX_end(ctx);
																 throw;
															 }

															 BN_CTX_end(ctx);
															 return prime;
																					 }

																					 CBigNum GeneratePrimeFromSeed(const uint256& seed, uint32_t primeBitLen,
																												   uint32_t *prime_gen_counter) {
																						 return GenerateRandomPrime(primeBitLen, seed, nullptr, prime_gen_counter);
																												   }

																												   CBigNum CalculateGroupModulus(const std::string& groupName, const uint256& seed,
																																				 uint32_t securityLevel, uint32_t *pLen, uint32_t *qLen) {
																													   // Determine p and q lengths based on security level
																													   uint32_t pBitLen, qBitLen;

																													   switch (securityLevel) {
																														   case 80:
																															   pBitLen = 1024;
																															   qBitLen = 256;
																															   break;
																														   case 112:
																															   pBitLen = 2048;
																															   qBitLen = 256;
																															   break;
																														   case 128:
																															   pBitLen = 3072;
																															   qBitLen = 320;
																															   break;
																														   case 192:
																															   pBitLen = 7680;
																															   qBitLen = 384;
																															   break;
																														   case 256:
																															   pBitLen = 15360;
																															   qBitLen = 512;
																															   break;
																														   default:
																															   throw std::runtime_error("Unsupported security level: " + std::to_string(securityLevel));
																													   }

																													   if (pLen) *pLen = pBitLen;
																													   if (qLen) *qLen = qBitLen;

																													   // Generate p
																													   CBigNum emptyModulus(0);
																													   std::string pAuxString = "";
																													   uint256 pSeed = CalculateSeed(emptyModulus, pAuxString, securityLevel, groupName + "_p");
																													   CBigNum p = GenerateRandomPrime(pBitLen, pSeed);

																													   // Generate q
																													   uint256 qSeed = CalculateSeed(p, pAuxString, securityLevel, groupName + "_q");
																													   CBigNum q = GenerateRandomPrime(qBitLen, qSeed);

																													   // Calculate n = p * q
																													   CAutoBN_CTX ctx;
																													   CBigNum n;

																													   if (!BN_mul(n.get(), p.get(), q.get(), ctx)) {
																														   throw std::runtime_error("BN_mul failed in CalculateGroupModulus");
																													   }

																													   // Verify bit length
																													   unsigned int actualBits = BN_num_bits(n.get());
																													   unsigned int expectedBits = pBitLen + qBitLen;

																													   if (actualBits != expectedBits) {
																														   std::stringstream ss;
																														   ss << "Generated modulus has wrong bit length: " << actualBits
																														   << " (expected " << expectedBits << ")";
																														   throw std::runtime_error(ss.str());
																													   }

																													   return n;
																																				 }

																																				 CBigNum CalculateGroupGenerator(const uint256& seed, const CBigNum& modulus,
																																												 const CBigNum& groupOrder, const std::string& groupName,
																	 uint32_t index) {
																																					 // Calculate generator seed
																																					 uint256 generatorSeed = CalculateGeneratorSeed(seed, modulus, groupName, index);

																																					 CAutoBN_CTX ctx;
																																					 BN_CTX_start(ctx);

																																					 try {
																																						 unsigned int count = 0;
																																						 while (true) {
																																							 // Calculate candidate = SHA256(generatorSeed || count) mod modulus
																																							 CHashWriter hasher(0,0);
																																							 hasher.write((const char*)&generatorSeed, sizeof(generatorSeed));
																																							 hasher.write((const char*)&count, sizeof(count));

																																							 uint256 candidateHash = hasher.GetHash();

																																							 CBigNum candidate;
																																							 BN_bin2bn(candidateHash.begin(), 32, candidate.get());

																																							 // Reduce modulo modulus
																																							 if (!BN_mod(candidate.get(), candidate.get(), modulus.get(), ctx)) {
																																								 throw std::runtime_error("BN_mod failed");
																																							 }

																																							 // Skip zero
																																							 if (BN_is_zero(candidate.get())) {
																																								 count++;
																																								 continue;
																																							 }

																																							 // Check if candidate is in the subgroup of order groupOrder
																																							 // candidate^groupOrder mod modulus should be 1
																																							 CBigNum result;
																																							 if (!BN_mod_exp(result.get(), candidate.get(), groupOrder.get(), modulus.get(), ctx)) {
																																								 throw std::runtime_error("BN_mod_exp failed");
																																							 }

																																							 if (BN_is_one(result.get())) {
																																								 // Found a valid generator
																																								 BN_CTX_end(ctx);
																																								 return candidate;
																																							 }

																																							 count++;

																																							 // Safety check
																																							 if (count > 100000) {
																																								 throw std::runtime_error("Failed to find generator after 100,000 iterations");
																																							 }
																																						 }
																																					 }
																																					 catch (...) {
																																						 BN_CTX_end(ctx);
																																						 throw;
																																					 }
																	 }

																	 // Test parameters for development
																	 ZerocoinParams* ZerocoinParams::GetTestParams() {
																		 static ZerocoinParams* testParams = nullptr;

																		 if (!testParams) {
																			 testParams = new ZerocoinParams();
																			 testParams->initialized = true;
																			 testParams->securityLevel = 80;

																			 // Small safe prime for testing: 2^255 - 19 (Curve25519 prime)
																			 testParams->accumulatorParams.accumulatorModulus.SetHex(
																				 "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");

																			 testParams->accumulatorParams.maxCoinValue =
																			 testParams->accumulatorParams.accumulatorModulus - CBigNum(1);
																			 testParams->accumulatorParams.minCoinValue = CBigNum(1);

																			 // For testing, use small values
																			 testParams->accumulatorParams.accumulatorBase.SetHex("2");
																			 testParams->accumulatorParams.k_prime.SetHex("10001");
																			 testParams->accumulatorParams.k_dprime.SetHex("10001");

																			 // Coin commitment group (using small values for testing)
																			 testParams->coinCommitmentGroup.modulus.SetHex(
																				 "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
																			 testParams->coinCommitmentGroup.groupOrder.SetHex(
																				 "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
																			 testParams->coinCommitmentGroup.g.SetHex("2");
																			 testParams->coinCommitmentGroup.h.SetHex("3");

																			 // Serial number commitment group (same as coin commitment for testing)
																			 testParams->serialNumberSoKCommitmentGroup = testParams->coinCommitmentGroup;
																		 }

																		 return testParams;
																	 }

																	 bool ZerocoinParams::SaveToFile(const std::string& filepath) const {
																		 // Stub implementation - in real code, this would serialize to file
																		 std::cerr << "Warning: SaveToFile not implemented" << std::endl;
																		 return false;
																	 }

																	 ZerocoinParams* ZerocoinParams::LoadFromFile(const std::string& filepath) {
																		 // Stub implementation - in real code, this would load from file
																		 std::cerr << "Warning: LoadFromFile not implemented, returning test params" << std::endl;
																		 return GetTestParams();
																	 }

} /* namespace libzerocoin */

#ifdef __clang__
#pragma clang diagnostic pop
#endif
