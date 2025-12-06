#ifndef BITCOIN_BIGNUM_SERIALIZE_H
#define BITCOIN_BIGNUM_SERIALIZE_H

//
// ⚠️ FILE ABBREVIATO — SOLO LE PARTI CHE ERANO ROTTE SONO RIPORTATE
//

#include <vector>
#include <stdint.h>
#include <string>
#include "uint256.h"

// … tutto il resto del file originale rimane invariato …

// 🔥 FIX: rimuovere default argument (=0) qui
template<typename Stream, typename C>
void Serialize(Stream& os, const std::basic_string<C>& str, int, int);

template<typename Stream, typename C>
void Unserialize(Stream& is, std::basic_string<C>& str, int, int);

#endif // BITCOIN_BIGNUM_SERIALIZE_H
