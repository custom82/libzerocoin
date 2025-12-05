// Copyright (c) 2017 The Zerocoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LIBZEROCOIN_H_
#define LIBZEROCOIN_H_

// AGGIUNGI SOLO QUESTA LINEA per OpenSSL 3.x compatibility
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define OPENSSL_API_COMPAT 0x30000000L
#endif

// TUTTO IL RESTO DEL FILE RIMANE INVARIATO
#include <stdexcept>
#include <string>
#include <vector>
#include <list>

#include "bitcoin_bignum/bignum.h"
#include "bitcoin_bignum/uint256.h"

namespace libzerocoin {
	// ... tutto il codice esistente invariato ...
} // namespace libzerocoin

#endif // LIBZEROCOIN_H_
