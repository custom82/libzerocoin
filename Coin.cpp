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
#include <openssl/provider.h>  // <-- AGGIUNGI QUESTO
#include <stdexcept>

using namespace std;

namespace libzerocoin {

	// AGGIUNGI: Inizializzazione OpenSSL 3.x
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

	// MODIFICA: EncryptSerialNumber - usa EVP_CIPHER_CTX_new() invece del vecchio stile
	vector<unsigned char> EncryptSerialNumber(const CBigNum& serialNumber, const unsigned char* key)
	{
		vector<unsigned char> ciphertext;

		// AGGIUNGI: Inizializza OpenSSL 3.x
		#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		init_openssl_3_if_needed();
		#endif

		// SOSTITUISCI: EVP_CIPHER_CTX ctx; -> EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		if (!ctx) {
			throw runtime_error("EncryptSerialNumber: EVP_CIPHER_CTX_new failed");
		}

		try {
			unsigned char iv[16];
			RAND_bytes(iv, sizeof(iv));

			// RIMANE INVARIATO:
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

			// SOSTITUISCI: EVP_CIPHER_CTX_cleanup(&ctx); -> EVP_CIPHER_CTX_free(ctx);
			EVP_CIPHER_CTX_free(ctx);
		} catch (...) {
			EVP_CIPHER_CTX_free(ctx);
			throw;
		}

		return ciphertext;
	}

	// MODIFICA ANCHE: DecryptSerialNumber - stesso principio
	CBigNum DecryptSerialNumber(const vector<unsigned char>& ciphertext, const unsigned char* key)
	{
		if (ciphertext.size() < 16) {
			throw runtime_error("DecryptSerialNumber: ciphertext too short");
		}

		// AGGIUNGI: Inizializza OpenSSL 3.x
		#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		init_openssl_3_if_needed();
		#endif

		unsigned char iv[16];
		memcpy(iv, &ciphertext[0], sizeof(iv));

		// SOSTITUISCI: EVP_CIPHER_CTX ctx; -> EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
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

			// SOSTITUISCI: EVP_CIPHER_CTX_cleanup(&ctx); -> EVP_CIPHER_CTX_free(ctx);
			EVP_CIPHER_CTX_free(ctx);
			return serialNumber;
		} catch (...) {
			EVP_CIPHER_CTX_free(ctx);
			throw;
		}
	}

	// ... resto del file invariato ...
} // namespace libzerocoin
