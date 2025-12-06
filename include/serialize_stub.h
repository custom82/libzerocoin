#ifndef LIBZEROCOIN_SERIALIZE_STUB_H
#define LIBZEROCOIN_SERIALIZE_STUB_H

#include <cstdint>
#include <type_traits>

// Usa le primitive bignum e hash già presenti nel tree "reale"
#include "bignum.h"
#include "hash.h"
#include "uint256.h"

namespace libzerocoin
{

    // Azioni "fake" per la serializzazione in stile Bitcoin
    struct CSerActionSerialize {};
    struct CSerActionUnserialize {};

    // Helper generico: scrittura
    template <typename Stream, typename T>
    inline void SerReadWrite(Stream &s, T &obj, CSerActionSerialize)
    {
        s << obj;
    }

    // Helper generico: lettura
    template <typename Stream, typename T>
    inline void SerReadWrite(Stream &s, T &obj, CSerActionUnserialize)
    {
        s >> obj;
    }

    // Macro base usata in tutti i SerializationOp(...)
    #define READWRITE(obj) SerReadWrite(s, obj, ser_action)

    // Implementazione compatibile con lo stile:
    //
    // IMPLEMENT_SERIALIZE
    // (
    //     READWRITE(x);
    //     READWRITE(y);
    // )
    //
    #define IMPLEMENT_SERIALIZE(body)                                                \
    template <typename Stream, typename Operation>                               \
    inline void SerializationOp(Stream &s, Operation ser_action)                 \
    {                                                                            \
        body                                                                     \
    }

    // Macro che aggiunge Serialize/Unserialize che chiamano SerializationOp.
    // IMPORTANTE: qui NON dichiariamo / definiamo SerializationOp, così non
    // andiamo in conflitto con le definizioni esplicite nelle classi.
    #define ADD_SERIALIZE_METHODS                                                    \
    template <typename Stream>                                                   \
    inline void Serialize(Stream &s) const                                       \
    {                                                                            \
        auto *self = const_cast<std::remove_const_t<decltype(*this)> *>(this);   \
        self->SerializationOp(s, CSerActionSerialize());                         \
    }                                                                            \
    \
    template <typename Stream>                                                   \
    inline void Unserialize(Stream &s)                                           \
    {                                                                            \
        SerializationOp(s, CSerActionUnserialize());                             \
    }

} // namespace libzerocoin

#endif // LIBZEROCOIN_SERIALIZE_STUB_H
