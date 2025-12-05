// Copyright (c) 2017 The Zerocoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LIBZEROCOIN_H_
#define LIBZEROCOIN_H_

// OPENSSL 3.x COMPATIBILITY - AGGIUNGI QUESTE 3 RIGHE
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define OPENSSL_API_COMPAT 0x30000000L
#endif

#include <stdexcept>
#include <string>
#include <vector>
#include <list>

#include "bitcoin_bignum/bignum.h"
#include "bitcoin_bignum/uint256.h"

namespace libzerocoin {

	// ... TUTTO IL RESTO DEL FILE RIMANE COSÌ COM'È ...
	// Non modificare nulla oltre alle 3 righe sopra

} // namespace libzerocoin

#endif // LIBZEROCOIN_H_
