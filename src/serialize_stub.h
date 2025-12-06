#pragma once
#ifndef LIBZEROCOIN_SERIALIZE_STUB_H
#define LIBZEROCOIN_SERIALIZE_STUB_H

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <stdexcept>
#include <type_traits>

#include "bitcoin_bignum/uint256.h"
#include "bitcoin_bignum/hash.h"
#include "bitcoin_bignum/bignum.h"

// -----------------------------------------------------------------------------
// Costanti minime per compatibilità con il codice stile Bitcoin
// -----------------------------------------------------------------------------

// Flag di "tipo" usato da HashWriter / CDataStream per calcolo hash
static const int SER_GETHASH = 1;

// Versione protocollo: per i nostri scopi è irrilevante, basta un valore fisso
static const int PROTOCOL_VERSION = 1;

// -----------------------------------------------------------------------------
// Stub CDataStream: buffer in memoria con operator<< / >>
// Sufficiente per far compilare hash.h (Hash(const T& v)) e eventuali usi base.
// -----------------------------------------------------------------------------

class CDataStream {
public:
    std::vector<unsigned char> vch;
    int nType;
    int nVersion;

    CDataStream(int nTypeIn = 0, int nVersionIn = 0)
    : nType(nTypeIn), nVersion(nVersionIn) {}

    const unsigned char* begin() const {
        return vch.empty() ? nullptr : &vch[0];
    }

    const unsigned char* end() const {
        return vch.empty() ? nullptr : (&vch[0] + vch.size());
    }

    size_t size() const { return vch.size(); }

    CDataStream& write(const char* pch, size_t size) {
        if (size == 0) return *this;
        const unsigned char* p = reinterpret_cast<const unsigned char*>(pch);
        vch.insert(vch.end(), p, p + size);
        return *this;
    }

    template <typename T>
    CDataStream& operator<<(const T& obj) {
        // Implementazione "grezza": copia binaria di T
        // (non è compatibile con il wire-format Bitcoin, ma ci basta per gli hash)
        static_assert(std::is_trivially_copyable<T>::value,
                      "CDataStream::operator<< richiede tipo trivially copyable");
        const unsigned char* p = reinterpret_cast<const unsigned char*>(&obj);
        vch.insert(vch.end(), p, p + sizeof(T));
        return *this;
    }

    template <typename T>
    CDataStream& operator>>(T& obj) {
        static_assert(std::is_trivially_copyable<T>::value,
                      "CDataStream::operator>> richiede tipo trivially copyable");
        if (vch.size() < sizeof(T))
            throw std::runtime_error("CDataStream::operator>> : not enough data");
        std::memcpy(&obj, begin(), sizeof(T));
        vch.erase(vch.begin(), vch.begin() + sizeof(T));
        return *this;
    }
};

// -----------------------------------------------------------------------------
// Stub CHashWriter: accumula bytes e calcola un uint256 con Hash(begin,end)
// -----------------------------------------------------------------------------

class CHashWriter {
public:
    int nType;
    int nVersion;
    CDataStream ss;

    CHashWriter(int nTypeIn, int nVersionIn)
    : nType(nTypeIn), nVersion(nVersionIn), ss(nTypeIn, nVersionIn) {}

    CHashWriter& write(const char* pch, size_t size) {
        ss.write(pch, size);
        return *this;
    }

    template <typename T>
    CHashWriter& operator<<(const T& obj) {
        ss << obj;
        return *this;
    }

    uint256 GetHash() const {
        if (ss.size() == 0)
            return uint256();
        // Usa l'implementazione già presente in bitcoin_bignum/hash.h
        return Hash(ss.vch.begin(), ss.vch.end());
    }
};

// -----------------------------------------------------------------------------
// Stub CSHA256: interfaccia simile a quella del core Bitcoin, ma semplificata.
// Viene usata solo per checksum in libzerocoin; qui la implementiamo sopra
// CHashWriter.
// -----------------------------------------------------------------------------

class CSHA256 {
public:
    CSHA256() : writer(SER_GETHASH, PROTOCOL_VERSION) {}

    CSHA256& Write(const unsigned char* data, size_t len) {
        writer.write(reinterpret_cast<const char*>(data), len);
        return *this;
    }

    // Ritorna l'hash SHA256 (in realtà double-SHA256 compatibile con Hash())
    void Finalize(unsigned char hash[32]) {
        uint256 h = writer.GetHash();
        // Copia i 32 byte del uint256 nel buffer di output.
        // uint256 nel codice Bitcoin espone begin()/end().
        const unsigned char* p = (const unsigned char*)&h;
        std::memcpy(hash, p, 32);
    }

    // Reset "best effort": ricrea il writer
    CSHA256& Reset() {
        writer = CHashWriter(SER_GETHASH, PROTOCOL_VERSION);
        return *this;
    }

private:
    CHashWriter writer;
};

// -----------------------------------------------------------------------------
// Macro di serializzazione stub: fanno compilar il codice ma NON serializzano.
// Questo è sufficiente se libzerocoin viene usato solo per generare/verificare
// prove in memoria e non per salvare oggetti su disco / rete.
// -----------------------------------------------------------------------------

// In Bitcoin questi macro generano Serialize/Unserialize + SerializationOp.
// Qui li riduciamo a no-op per non rompere le firme dei classi.

#define IMPLEMENT_SERIALIZE /* no-op stub */

// ADD_SERIALIZE_METHODS viene usato come:
//   ADD_SERIALIZE_METHODS;
//   template<typename Stream, typename Operation>
//   inline void SerializationOp(Stream& s, Operation ser_action) { ... }
// quindi lo lasciamo vuoto.
#define ADD_SERIALIZE_METHODS /* no-op stub */

// READWRITE(x) viene usato dentro SerializationOp; qui lo rendiamo un no-op
// che evita warning "unused variable".
#define READWRITE(obj) do { (void)(obj); } while (0)

// -----------------------------------------------------------------------------
// Tipi Zerocoin "mancanti": CoinDenomination, ZEROCOIN_VERSION, ecc.
// Se esistono già definizioni altrove, puoi commentare queste righe.
// -----------------------------------------------------------------------------

namespace libzerocoin {

    #ifndef LIBZEROCOIN_HAVE_COIN_DENOMINATION
    // Definizione minimale. I valori reali non sono critici per la compilazione;
    // è importante solo ZQ_LOVELACE che viene usato come default.
    enum CoinDenomination {
        ZQ_LOVELACE = 1
    };
    #endif

} // namespace libzerocoin

#ifndef ZEROCOIN_VERSION
// Versione di default; per molti usi di libzerocoin è sufficiente 1.
#define ZEROCOIN_VERSION 1
#endif

#endif // LIBZEROCOIN_SERIALIZE_STUB_H
