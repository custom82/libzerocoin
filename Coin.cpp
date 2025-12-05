// Copyright (c) 2017 The Zerocoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Coin.h"
#include "Commitment.h"
#include "Zerocoin.h"
#include <iostream>
#include <sstream>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/provider.h>  // AGGIUNTO: per OpenSSL 3.x
#include <stdexcept>

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

	PublicCoin::PublicCoin(const Params* p):
	params(p) {
		if (this->params->initialized) {
			this->randomize();
		}
	};

	PublicCoin::PublicCoin(const Params* p, const CBigNum& coin, const CoinDenomination d):
	params(p), value(coin), denomination(d) {
	};

	bool PublicCoin::validate() const {
		if (this->params->accumulatorParams.minCoinValue >= value) {
			return false;
		}
		if (this->params->accumulatorParams.maxCoinValue <= value) {
			return false;
		}
		if (!value.isPrime(params->zkp_iterations)) {
			return false;
		}
		return true;
	}

	PrivateCoin::PrivateCoin(const Params* p, const CoinDenomination denomination):
	params(p), publicCoin(p) {
		if (!this->params->initialized) {
			throw std::runtime_error("PrivateCoin: parameters not initialized");
		}

		this->denomination = denomination;
		this->serialNumber = CBigNum::randBignum(this->params->coinCommitmentParams.groupOrder);
		this->randomness = CBigNum::randBignum(this->params->coinCommitmentParams.groupOrder);

		this->commitment = Commitment(&this->params->coinCommitmentParams,
									  this->serialNumber,
								this->randomness);

		this->publicCoin = PublicCoin(p, this->commitment.getCommitmentValue(), denomination);
	}

	const PublicCoin& PrivateCoin::getPublicCoin() const {
		return this->publicCoin;
	}

	const CBigNum& PrivateCoin::getSerialNumber() const {
		return this->serialNumber;
	}

	const CBigNum& PrivateCoin::getRandomness() const {
		return this->randomness;
	}

	const unsigned char* PrivateCoin::getEcdsaSecretKey() const {
		return this->ecdsaSecretKey;
	}

	vector<unsigned char> EncryptSerialNumber(const CBigNum& serialNumber, const unsigned char* key)
	{
		vector<unsigned char> ciphertext;

		// AGGIUNTO: Inizializza OpenSSL 3.x
		#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		init_openssl_3_if_needed();
		#endif

		// MODIFICATO: Nuova API EVP
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		if (!ctx) {
			throw runtime_error("EncryptSerialNumber: EVP_CIPHER_CTX_new failed");
		}

		try {
			unsigned char iv[16];
			#if OPENSSL_VERSION_NUMBER >= 0x30000000L
			init_openssl_3_if_needed();
			#endif
			RAND_bytes(iv, sizeof(iv));

			if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
				throw runtime_error("EncryptSerialNumber: EVP_EncryptInit_ex failed");
			}

			vector<unsigned char> plaintext = serialNumber.getvch();
			ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
			int out_len = 0;

			if (EVP_EncryptUpdate(ctx, &ciphertext[0], &out_len,
				&plaintext[0], plaintext.size()) != 1) {
				throw runtime_error("EncryptSerialNumber: EVP_EncryptUpdate failed");
				}

				int final_len = 0;
			if (EVP_EncryptFinal_ex(ctx, &ciphertext[out_len], &final_len) != 1) {
				throw runtime_error("EncryptSerialNumber: EVP_EncryptFinal_ex failed");
			}

			out_len += final_len;
			ciphertext.resize(out_len);
			ciphertext.insert(ciphertext.begin(), iv, iv + sizeof(iv));

			// MODIFICATO: Nuova API per liberare risorse
			EVP_CIPHER_CTX_free(ctx);
		} catch (...) {
			EVP_CIPHER_CTX_free(ctx);
			throw;
		}

		return ciphertext;
	}

	CBigNum DecryptSerialNumber(const vector<unsigned char>& ciphertext, const unsigned char* key)
	{
		if (ciphertext.size() < 16) {
			throw runtime_error("DecryptSerialNumber: ciphertext too short");
		}

		// AGGIUNTO: Inizializza OpenSSL 3.x
		#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		init_openssl_3_if_needed();
		#endif

		unsigned char iv[16];
		memcpy(iv, &ciphertext[0], sizeof(iv));

		// MODIFICATO: Nuova API EVP
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		if (!ctx) {
			throw runtime_error("DecryptSerialNumber: EVP_CIPHER_CTX_new failed");
		}

		try {
			if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
				throw runtime_error("DecryptSerialNumber: EVP_DecryptInit_ex failed");
			}

			vector<unsigned char> plaintext(ciphertext.size() - sizeof(iv));
			int out_len = 0;

			if (EVP_DecryptUpdate(ctx, &plaintext[0], &out_len,
				&ciphertext[sizeof(iv)], ciphertext.size() - sizeof(iv)) != 1) {
				throw runtime_error("DecryptSerialNumber: EVP_DecryptUpdate failed");
				}

				int final_len = 0;
			if (EVP_DecryptFinal_ex(ctx, &plaintext[out_len], &final_len) != 1) {
				throw runtime_error("DecryptSerialNumber: EVP_DecryptFinal_ex failed");
			}

			out_len += final_len;
			plaintext.resize(out_len);

			CBigNum serialNumber;
			serialNumber.setvch(plaintext);

			// MODIFICATO: Nuova API per liberare risorse
			EVP_CIPHER_CTX_free(ctx);
			return serialNumber;
		} catch (...) {
			EVP_CIPHER_CTX_free(ctx);
			throw;
		}
	}

	vector<unsigned char> PrivateCoin::serialize() const
	{
		vector<unsigned char> buffer;
		buffer.push_back((unsigned char)this->denomination);

		vector<unsigned char> serialBytes = this->serialNumber.getvch();
		buffer.insert(buffer.end(), serialBytes.begin(), serialBytes.end());

		vector<unsigned char> randomBytes = this->randomness.getvch();
		buffer.insert(buffer.end(), randomBytes.begin(), randomBytes.end());

		buffer.push_back(0xFF);

		return buffer;
	}

	PrivateCoin PrivateCoin::deserialize(const Params* params, const vector<unsigned char>& buffer)
	{
		if (buffer.empty()) {
			throw runtime_error("PrivateCoin::deserialize: empty buffer");
		}

		CoinDenomination denomination = (CoinDenomination)buffer[0];

		size_t sep_pos = 0;
		for (size_t i = 1; i < buffer.size(); i++) {
			if (buffer[i] == 0xFF) {
				sep_pos = i;
				break;
			}
		}

		if (sep_pos == 0 || sep_pos >= buffer.size() - 1) {
			throw runtime_error("PrivateCoin::deserialize: invalid format");
		}

		vector<unsigned char> serialBytes(buffer.begin() + 1, buffer.begin() + sep_pos);
		CBigNum serialNumber;
		serialNumber.setvch(serialBytes);

		vector<unsigned char> randomBytes(buffer.begin() + sep_pos + 1, buffer.end());
		CBigNum randomness;
		randomness.setvch(randomBytes);

		PrivateCoin coin(params, denomination);
		coin.serialNumber = serialNumber;
		coin.randomness = randomness;

		coin.commitment = Commitment(&params->coinCommitmentParams,
									 serialNumber,
							   randomness);

		coin.publicCoin = PublicCoin(params, coin.commitment.getCommitmentValue(), denomination);

		return coin;
	}

} // namespace libzerocoin
