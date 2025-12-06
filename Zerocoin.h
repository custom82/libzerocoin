// Copyright (c) 2017-2022 The Phore developers
// Copyright (c) 2017-2022 The Phoq developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZEROCOIN_H
#define ZEROCOIN_H

#include "bitcoin_bignum/bignum.h"
#include "Coin.h"
#include "CoinSpend.h"
#include "Params.h"
#include "Accumulator.h"
#include "AccumulatorProofOfKnowledge.h"
#include "SerialNumberSignatureOfKnowledge.h"
#include "Commitment.h"
#include "CommitmentProofOfKnowledge.h"
#include "SpendMetaData.h"

// OpenSSL 3.5 compatibility
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

namespace libzerocoin {

	/** Main API for libzerocoin.
	 */
	class Zerocoin {
	public:
		/** Generate a new zerocoin private key.
		 *
		 * @param params zerocoin params
		 * @param denomination the denomination of the coin
		 * @param version the version of the coin
		 * @return PrivateCoin the new private coin
		 */
		static PrivateCoin MintCoin(const ZerocoinParams& params, CoinDenomination denomination, int version = ZEROCOIN_VERSION);

		/** Mint a new zerocoin private key with a precomputed accumulator witness.
		 *
		 * @param params zerocoin params
		 * @param denomination the denomination of the coin
		 * @param version the version of the coin
		 * @param witness the accumulator witness
		 * @return PrivateCoin the new private coin
		 */
		static PrivateCoin MintCoinFast(const ZerocoinParams& params, CoinDenomination denomination, int version, Accumulator& witness);

		/** Mint a new zerocoin with a specific serial number.
		 *
		 * @param params zerocoin params
		 * @param denomination the denomination of the coin
		 * @param version the version of the coin
		 * @param serial the serial number to use
		 * @return PrivateCoin the new private coin
		 */
		static PrivateCoin MintCoinWithSerial(const ZerocoinParams& params, CoinDenomination denomination, int version, const CBigNum& serial);

		/** Spend a zerocoin.
		 *
		 * @param params zerocoin params
		 * @param coin the private coin to spend
		 * @param accumulator the accumulator containing the coin
		 * @param checksum the checksum of the accumulator
		 * @param msghash hash of the transaction
		 * @param metadata spend metadata
		 * @return CoinSpend the coin spend proof
		 */
		static CoinSpend SpendCoin(const ZerocoinParams& params, const PrivateCoin& coin, Accumulator& accumulator,
								   const uint32_t checksum, const uint256& msghash, const SpendMetaData& metadata);

		/** Spend a zerocoin without metadata.
		 *
		 * @param params zerocoin params
		 * @param coin the private coin to spend
		 * @param accumulator the accumulator containing the coin
		 * @param checksum the checksum of the accumulator
		 * @return CoinSpend the coin spend proof
		 */
		static CoinSpend SpendCoin(const ZerocoinParams& params, const PrivateCoin& coin, Accumulator& accumulator,
								   const uint32_t checksum);

		/** Verify a coin spend proof.
		 *
		 * @param params zerocoin params
		 * @param spend the coin spend proof
		 * @param accumulator the accumulator containing the coin
		 * @param checksum the checksum of the accumulator
		 * @return true if valid
		 */
		static bool VerifySpend(const ZerocoinParams& params, const CoinSpend& spend, const Accumulator& accumulator,
								const uint32_t checksum);

		/** Verify a coin's public parameters.
		 *
		 * @param params zerocoin params
		 * @param coin the public coin
		 * @return true if valid
		 */
		static bool VerifyCoin(const ZerocoinParams& params, const PublicCoin& coin);

		/** Calculate the accumulator checksum.
		 *
		 * @param coins the coins in the accumulator
		 * @return uint32_t the checksum
		 */
		static uint32_t CalculateChecksum(const std::vector<PublicCoin>& coins);

		/** Calculate the accumulator checksum from a single coin.
		 *
		 * @param coin the coin
		 * @return uint32_t the checksum
		 */
		static uint32_t CalculateChecksum(const PublicCoin& coin);

		/** Get the denomination amount in atomic units.
		 *
		 * @param denomination the denomination
		 * @return int64_t the amount
		 */
		static int64_t DenominationToAmount(CoinDenomination denomination);

		/** Get the denomination from an amount.
		 *
		 * @param amount the amount
		 * @return CoinDenomination the denomination
		 */
		static CoinDenomination AmountToDenomination(int64_t amount);

		/** Get the string representation of a denomination.
		 *
		 * @param denomination the denomination
		 * @return std::string the string
		 */
		static std::string DenominationToString(CoinDenomination denomination);

		/** Get the denomination from a string.
		 *
		 * @param str the string
		 * @return CoinDenomination the denomination
		 */
		static CoinDenomination StringToDenomination(const std::string& str);

		/** Get the list of available denominations.
		 *
		 * @return std::vector<CoinDenomination> the list
		 */
		static std::vector<CoinDenomination> GetStandardDenominations();

		/** Check if an amount is a standard denomination.
		 *
		 * @param amount the amount
		 * @return true if standard
		 */
		static bool IsStandardDenominationAmount(int64_t amount);

		/** Check if a denomination is valid.
		 *
		 * @param denomination the denomination
		 * @return true if valid
		 */
		static bool IsValidDenomination(CoinDenomination denomination);

		/** Get the maximum number of coins per transaction.
		 *
		 * @return size_t the maximum number
		 */
		static size_t GetMaxCoinsPerTransaction();

		/** Get the security level.
		 *
		 * @return int the security level
		 */
		static int GetSecurityLevel();

		/** Set the security level.
		 *
		 * @param level the security level
		 */
		static void SetSecurityLevel(int level);

		/** Get the zerocoin modulus.
		 *
		 * @param params zerocoin params
		 * @return CBigNum the modulus
		 */
		static CBigNum GetModulus(const ZerocoinParams& params);

		/** Generate random number within range.
		 *
		 * @param max the maximum value
		 * @return CBigNum the random number
		 */
		static CBigNum RandomBignum(const CBigNum& max);

		/** Generate random number with specified bit length.
		 *
		 * @param bits the number of bits
		 * @return CBigNum the random number
		 */
		static CBigNum RandomBignum(int bits);

		/** Generate a prime number with specified bit length.
		 *
		 * @param bits the number of bits
		 * @return CBigNum the prime number
		 */
		static CBigNum GeneratePrime(int bits);

		/** Compute a^b mod m.
		 *
		 * @param a base
		 * @param b exponent
		 * @param m modulus
		 * @return CBigNum the result
		 */
		static CBigNum PowMod(const CBigNum& a, const CBigNum& b, const CBigNum& m);

		/** Compute a * b mod m.
		 *
		 * @param a first factor
		 * @param b second factor
		 * @param m modulus
		 * @return CBigNum the result
		 */
		static CBigNum MulMod(const CBigNum& a, const CBigNum& b, const CBigNum& m);

		/** Compute a + b mod m.
		 *
		 * @param a first term
		 * @param b second term
		 * @param m modulus
		 * @return CBigNum the result
		 */
		static CBigNum AddMod(const CBigNum& a, const CBigNum& b, const CBigNum& m);

		/** Compute a - b mod m.
		 *
		 * @param a first term
		 * @param b second term
		 * @param m modulus
		 * @return CBigNum the result
		 */
		static CBigNum SubMod(const CBigNum& a, const CBigNum& b, const CBigNum& m);

		/** Compute the modular inverse of a mod m.
		 *
		 * @param a the number
		 * @param m the modulus
		 * @return CBigNum the inverse
		 */
		static CBigNum ModInverse(const CBigNum& a, const CBigNum& m);

		/** Compute the greatest common divisor of a and b.
		 *
		 * @param a first number
		 * @param b second number
		 * @return CBigNum the gcd
		 */
		static CBigNum Gcd(const CBigNum& a, const CBigNum& b);

		/** Compute the square root of a modulo a prime p.
		 *
		 * @param a the number
		 * @param p the prime modulus
		 * @return CBigNum the square root
		 */
		static CBigNum SqrtMod(const CBigNum& a, const CBigNum& p);

		/** Check if a number is prime.
		 *
		 * @param n the number
		 * @param checks number of Miller-Rabin checks
		 * @return true if prime
		 */
		static bool IsPrime(const CBigNum& n, int checks = 20);

		/** Compute the hash of data.
		 *
		 * @param data the data
		 * @param len the length
		 * @return uint256 the hash
		 */
		static uint256 Hash(const unsigned char* data, size_t len);

		/** Compute the hash of a vector.
		 *
		 * @param data the vector
		 * @return uint256 the hash
		 */
		static uint256 Hash(const std::vector<unsigned char>& data);

		/** Compute the hash of a string.
		 *
		 * @param str the string
		 * @return uint256 the hash
		 */
		static uint256 Hash(const std::string& str);

		/** Compute the hash of a big number.
		 *
		 * @param n the big number
		 * @return uint256 the hash
		 */
		static uint256 Hash(const CBigNum& n);
	};

} /* namespace libzerocoin */

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#endif /* ZEROCOIN_H */
