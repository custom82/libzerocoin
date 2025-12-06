#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

#include <cstdint>
#include <string>
#include <vector>
#include <cstring>

#include <openssl/sha.h>

#include "uint256.h"
#include "serialize.h"

// Writer stile Bitcoin: accumula dati e produce SHA256
class CHashWriter {
private:
    SHA256_CTX ctx;
    int nType;
    int nVersion;

public:
    CHashWriter(int nTypeIn, int nVersionIn)
    : nType(nTypeIn), nVersion(nVersionIn)
    {
        SHA256_Init(&ctx);
    }

    CHashWriter& write(const char* pch, size_t size)
    {
        SHA256_Update(&ctx,
                      reinterpret_cast<const unsigned char*>(pch),
                      size);
        return *this;
    }

    template <typename T>
    CHashWriter& operator<<(const T& obj)
    {
        ::Serialize(*this, obj, nType, nVersion);
        return *this;
    }

    void GetHash(unsigned char* out)
    {
        SHA256_CTX ctxCopy = ctx;
        SHA256_Final(out, &ctxCopy);
    }

    uint256 GetHash()
    {
        uint256 result;
        GetHash(reinterpret_cast<unsigned char*>(&result));
        return result;
    }
};

// Hash semplice di un buffer
inline uint256 Hash(const unsigned char* begin, const unsigned char* end)
{
    uint256 result;
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, begin, end - begin);
    SHA256_Final(reinterpret_cast<unsigned char*>(&result), &ctx);

    return result;
}

// Hash Bitcoin-compatibile di un oggetto serializzabile
template <typename T>
uint256 Hash(const T& v)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << v;
    return Hash(reinterpret_cast<const unsigned char*>(&ss[0]),
                reinterpret_cast<const unsigned char*>(&ss[0]) + ss.size());
}

#endif // BITCOIN_HASH_H
