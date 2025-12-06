// Copyright (c) 2017-2022 The Phore developers
// Copyright (c) 2017-2022 The Phoq developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARAMGENERATION_H
#define PARAMGENERATION_H

#include <string>
#include <cstdint>
#include "uint256.h"
#include "bitcoin_bignum/bignum.h"

// OpenSSL 3.5 compatibility
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

namespace libzerocoin {

    /**
     * @brief Calculate the seed for parameter generation
     *
     * @param modulus The modulus value
     * @param auxString Auxiliary string for seeding
     * @param securityLevel Security level (80, 112, 128, 192, 256)
     * @param groupName Name of the group
     * @return uint256 The calculated seed
     */
    uint256 CalculateSeed(const CBigNum& modulus, const std::string& auxString,
                          uint32_t securityLevel, std::string groupName);

    /**
     * @brief Calculate the generator seed
     *
     * @param seed Input seed
     * @param modulus The modulus
     * @param groupName Name of the group
     * @param index Index for generator calculation
     * @return uint256 The generator seed
     */
    uint256 CalculateGeneratorSeed(const uint256& seed, const CBigNum& modulus,
                                   const std::string& groupName, uint32_t index);

    /**
     * @brief Calculate SHA256 hash of input
     *
     * @param input Input to hash
     * @return uint256 The hash
     */
    uint256 CalculateHash(const uint256& input);

    /**
     * @brief Generate a random prime number
     *
     * @param primeBitLen Bit length of the prime
     * @param inSeed Input seed
     * @param outSeed Output seed (optional)
     * @param prime_gen_counter Prime generation counter (optional)
     * @return CBigNum The generated prime
     */
    CBigNum GenerateRandomPrime(uint32_t primeBitLen, const uint256& inSeed,
                                uint256 *outSeed = nullptr,
                                unsigned int *prime_gen_counter = nullptr);

    /**
     * @brief Generate a prime number from a seed
     *
     * @param seed Input seed
     * @param primeBitLen Bit length of the prime
     * @param prime_gen_counter Prime generation counter (optional)
     * @return CBigNum The generated prime
     */
    CBigNum GeneratePrimeFromSeed(const uint256& seed, uint32_t primeBitLen,
                                  uint32_t *prime_gen_counter = nullptr);

    /**
     * @brief Calculate the group modulus
     *
     * @param groupName Name of the group
     * @param seed Input seed
     * @param securityLevel Security level
     * @param pLen Length of p (output, optional)
     * @param qLen Length of q (output, optional)
     * @return CBigNum The group modulus
     */
    CBigNum CalculateGroupModulus(const std::string& groupName, const uint256& seed,
                                  uint32_t securityLevel,
                                  uint32_t *pLen = nullptr, uint32_t *qLen = nullptr);

    /**
     * @brief Calculate the group generator
     *
     * @param seed Input seed
     * @param modulus Group modulus
     * @param groupOrder Group order
     * @param groupName Name of the group
     * @param index Generator index
     * @return CBigNum The group generator
     */
    CBigNum CalculateGroupGenerator(const uint256& seed, const CBigNum& modulus,
                                    const CBigNum& groupOrder, const std::string& groupName,
                                    uint32_t index);

    /**
     * @brief Integer group parameters
     */
    struct IntegerGroupParams {
        CBigNum modulus;        // Modulus n
        CBigNum groupOrder;     // Order of the group
        CBigNum g;              // Generator g
        CBigNum h;              // Generator h

        IntegerGroupParams() {}

        /**
         * @brief Validate the group parameters
         *
         * @return true if valid
         */
        bool validate() const;

        ADD_SERIALIZE_METHODS;
        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            READWRITE(modulus);
            READWRITE(groupOrder);
            READWRITE(g);
            READWRITE(h);
        }
    };

    /**
     * @brief Accumulator parameters
     */
    struct AccumulatorAndProofParams {
        CBigNum accumulatorModulus;     // Accumulator modulus
        CBigNum accumulatorBase;        // Accumulator base (g)
        CBigNum minCoinValue;           // Minimum coin value
        CBigNum maxCoinValue;           // Maximum coin value
        CBigNum accumulatorPoKCommitmentGroupG;
        CBigNum accumulatorPoKCommitmentGroupH;
        CBigNum k_prime;
        CBigNum k_dprime;

        AccumulatorAndProofParams() {}

        /**
         * @brief Validate the accumulator parameters
         *
         * @return true if valid
         */
        bool validate() const;

        ADD_SERIALIZE_METHODS;
        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            READWRITE(accumulatorModulus);
            READWRITE(accumulatorBase);
            READWRITE(minCoinValue);
            READWRITE(maxCoinValue);
            READWRITE(accumulatorPoKCommitmentGroupG);
            READWRITE(accumulatorPoKCommitmentGroupH);
            READWRITE(k_prime);
            READWRITE(k_dprime);
        }
    };

    /**
     * @brief Zerocoin parameters structure
     */
    class ZerocoinParams {
    public:
        bool initialized;
        uint32_t securityLevel;

        // Accumulator parameters
        AccumulatorAndProofParams accumulatorParams;

        // Coin commitment group
        IntegerGroupParams coinCommitmentGroup;

        // Serial number signature of knowledge commitment group
        IntegerGroupParams serialNumberSoKCommitmentGroup;

        ZerocoinParams() : initialized(false), securityLevel(0) {}

        /**
         * @brief Initialize parameters
         *
         * @param N Modulus
         * @param security Security level
         * @return true if successful
         */
        bool initialize(const CBigNum& N, uint32_t security);

        /**
         * @brief Get test parameters for development
         *
         * @return ZerocoinParams* Test parameters
         */
        static ZerocoinParams* GetTestParams();

        /**
         * @brief Save parameters to file
         *
         * @param filepath File path
         * @return true if successful
         */
        bool SaveToFile(const std::string& filepath) const;

        /**
         * @brief Load parameters from file
         *
         * @param filepath File path
         * @return ZerocoinParams* Loaded parameters
         */
        static ZerocoinParams* LoadFromFile(const std::string& filepath);

        ADD_SERIALIZE_METHODS;
        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            READWRITE(initialized);
            READWRITE(securityLevel);
            READWRITE(accumulatorParams);
            READWRITE(coinCommitmentGroup);
            READWRITE(serialNumberSoKCommitmentGroup);
        }
    };

} /* namespace libzerocoin */

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#endif /* PARAMGENERATION_H */
