// Copyright (c) 2012-2013 The PPCoin developers
// Copyright (c) 2014 The BlackCoin developers
// Copyright (c) 2017-2022 The Phore developers
// Copyright (c) 2017-2022 The Phoq developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef COIN_H
#define COIN_H

#include "bitcoin_bignum/bignum.h"
#include "Accumulator.h"
#include "Commitment.h"
#include "Params.h"

// Serialization macros
#ifndef SERIALIZE_H
#define ADD_SERIALIZE_METHODS \
template<typename Stream, typename Operation> \
inline void SerializationOp(Stream& s, Operation ser_action)

#define READWRITE(...) { __VA_ARGS__ }

template<typename Stream>
inline void Serialize(Stream& s, const unsigned char* data, size_t size) {
	s.write(reinterpret_cast<const char*>(data), size);
}

template<typename Stream>
inline void Unserialize(Stream& s, unsigned char* data, size_t size) {
	s.read(reinterpret_cast<char*>(data), size);
}

#define FLATDATA(data) data, sizeof(data)
#endif

// OpenSSL 3.5 compatibility
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

namespace libzerocoin {

	/** Public coin class encapsulates the data of a public coin.
	 *
	 * Public coins are those that are intended to be visible to the entire network
	 * (ie: spend transactions). Private coins are those that are intended to be
	 * invisible (ie: mint transactions).
	 */
	class PublicCoin {
	public:
		PublicCoin(){};

		/**
		 * @brief Construct a new Public Coin object from a denomination and randomness
		 *
		 * @param p zerocoin params
		 * @param coin the value of the coin
		 * @param randomness randomness used to mint the coin
		 */
		PublicCoin(const ZerocoinParams* p, const CoinDenomination coin, const CBigNum& randomness);

		template<typename Stream>
		PublicCoin(const ZerocoinParams* p, Stream& strm) : params(p) {
			strm >> *this;
		}

		const CBigNum& getValue() const { return this->value; }
		CoinDenomination getDenomination() const { return this->denomination; }
		bool operator==(const PublicCoin& rhs) const {
			return ((this->value == rhs.value) && (this->params == rhs.params));
		}
		bool operator!=(const PublicCoin& rhs) const {
			return !(*this == rhs);
		}

		/** Checks that a coin prime is in the appropriate range given the parameters
		 * and that the coin is prime.
		 *
		 * @return true if valid
		 */
		bool validate() const;

		/**
		 * @brief Adds the public coin to the accumulator checksum
		 *
		 * @param checksum accumulator checksum to add the coin value to
		 */
		void addToChecksum(CSHA256& checksum) const;

		void setParams(const ZerocoinParams* p) { this->params = p; }

		ADD_SERIALIZE_METHODS;
		template <typename Stream, typename Operation>
		inline void SerializationOp(Stream& s, Operation ser_action) {
			READWRITE(value);
			READWRITE(denomination);
		}

	private:
		const ZerocoinParams* params;
		CBigNum value;
		CoinDenomination denomination;
	};

	/** Private coin class encapsulates the data of a private coin.
	 *
	 * Private coins are those that are intended to be invisible to the entire
	 * network (ie: mint transactions). Public coins are those that are intended to be
	 * visible (ie: spend transactions).
	 */
	class PrivateCoin {
	public:
		PrivateCoin(){};

		/**
		 * @brief Construct a new Private Coin object
		 *
		 * @param p zerocoin params
		 * @param denomination the denomination of the coin
		 * @param version the version of the coin
		 */
		PrivateCoin(const ZerocoinParams* p, const CoinDenomination denomination, int version = ZEROCOIN_VERSION);

		const CBigNum& getSerialNumber() const { return this->serialNumber; }
		const CBigNum& getRandomness() const { return this->randomness; }
		const CBigNum& getPublicCoinValue() const { return this->publicCoin.getValue(); }
		const PublicCoin& getPublicCoin() const { return this->publicCoin; }
		CoinDenomination getDenomination() const { return this->denomination; }
		int getVersion() const { return this->version; }
		void setPublicCoin(const PublicCoin& p) { this->publicCoin = p; }

		/** Mint a new coin
		 *
		 * @param version the version of the coin
		 */
		void mintCoin(const CoinDenomination denomination, int version = ZEROCOIN_VERSION);

		/**
		 * Mint a new coin using a faster process by using a pre-computed
		 * accumulator witness. This is intended to be used by the miner.
		 *
		 * @param denomination the denomination of the coin
		 * @param version the version of the coin
		 * @param witness the accumulator witness for the coin
		 */
		void mintCoinFast(const CoinDenomination denomination, int version, Accumulator& witness);

		/**
		 * Mint a new coin with a specific serial number
		 *
		 * @param denomination the denomination of the coin
		 * @param version the version of the coin
		 * @param serial the serial number to use
		 */
		void mintCoinWithSerial(const CoinDenomination denomination, int version, const CBigNum& serial);

	private:
		const ZerocoinParams* params;
		PublicCoin publicCoin;
		CBigNum serialNumber;
		CBigNum randomness;
		CoinDenomination denomination;
		int version = ZEROCOIN_VERSION;

		/**
		 * @brief Generate a new serial number
		 *
		 * @return CBigNum the new serial number
		 */
		void generateSerial();

		/**
		 * @brief Generate a new randomness value
		 *
		 * @return CBigNum the new randomness
		 */
		void generateRandomness();

		/**
		 * Creates a Pedersen commitment to the serial number and randomness
		 *
		 * @param commitment the commitment output
		 */
		void createCommitment(Commitment& commitment);
	};

} /* namespace libzerocoin */

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#endif /* COIN_H */
