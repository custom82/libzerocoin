// src/serialize_stub.h
#ifndef LIBZEROCOIN_SERIALIZE_STUB_H
#define LIBZEROCOIN_SERIALIZE_STUB_H

#include <vector>
#include <stdint.h>
#include <string>
#include "bitcoin_bignum/bignum.h"

namespace libzerocoin {

    // Alias compatibile con il codice originale
    using Bignum = CBigNum;

    // Tag-type usati dal framework di serializzazione di Bitcoin
    struct CSerActionSerialize {};
    struct CSerActionUnserialize {};

    // Stream minimale compatibile con CDataStream di Bitcoin.
    // Serve solo per far funzionare << e >> usati da Hash() e Serialize().
    class CDataStream {
    public:
        typedef std::vector<unsigned char> container_type;
        typedef container_type::iterator iterator;
        typedef container_type::const_iterator const_iterator;

        CDataStream(int /*nType*/, int /*nVersion*/) {}

        template <typename T>
        CDataStream& operator<<(const T& obj) {
            Serialize(*this, obj, 0, 0);
            return *this;
        }

        template <typename T>
        CDataStream& operator>>(T& obj) {
            Unserialize(*this, obj, 0, 0);
            return *this;
        }

        const_iterator begin() const { return vch.begin(); }
        const_iterator end() const { return vch.end(); }

        void write(const char* pch, size_t size) {
            vch.insert(vch.end(),
                       reinterpret_cast<const unsigned char*>(pch),
                       reinterpret_cast<const unsigned char*>(pch) + size);
        }

        void read(char* pch, size_t size) {
            if (size > vch.size())
                size = vch.size();
            std::copy(vch.begin(), vch.begin() + size,
                      reinterpret_cast<unsigned char*>(pch));
            vch.erase(vch.begin(), vch.begin() + size);
        }

    private:
        container_type vch;
    };

    // Macro compatibili con quelle di Bitcoin Core.
    // Se sono già definite altrove (per sicurezza) non le ridefiniamo.
    #ifndef READWRITE
    #define READWRITE(...) (s.*ser_action)(__VA_ARGS__)
    #endif

    #ifndef IMPLEMENT_SERIALIZE
    #define IMPLEMENT_SERIALIZE(                                                                 \
    ...)                                                                                     \
    template <typename Stream, typename Operation>                                           \
    inline void SerializationOp(Stream& s, Operation ser_action) {                           \
        __VA_ARGS__                                                                          \
    }                                                                                        \
    template <typename Stream>                                                              \
    inline void Serialize(Stream& s, int /*nType*/, int /*nVersion*/) const {               \
        SerializationOp(s, CSerActionSerialize());                                           \
    }                                                                                        \
    template <typename Stream>                                                              \
    inline void Unserialize(Stream& s, int /*nType*/, int /*nVersion*/) {                   \
        SerializationOp(s, CSerActionUnserialize());                                         \
    }
    #endif

    #ifndef ADD_SERIALIZE_METHODS
    #define ADD_SERIALIZE_METHODS                                                                \
    template <typename Stream, typename Operation>                                           \
    inline void SerializationOp(Stream& s, Operation ser_action);                            \
    template <typename Stream>                                                              \
    inline void Serialize(Stream& s, int nType, int nVersion) const {                       \
        SerializationOp(s, CSerActionSerialize());                                           \
    }                                                                                        \
    template <typename Stream>                                                              \
    inline void Unserialize(Stream& s, int nType, int nVersion) {                           \
        SerializationOp(s, CSerActionUnserialize());                                         \
    }
    #endif

} // namespace libzerocoin

#endif // LIBZEROCOIN_SERIALIZE_STUB_H
