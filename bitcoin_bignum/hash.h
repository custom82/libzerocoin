#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

#include <cstdint>
#include <string>
#include <vector>
#include <cstring>

#include <openssl/sha.h>

#include "uint256.h"

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

// Hash di buffer
inline uint256 Hash(const unsigned char* begin, const unsigned char* end)
{
    uint256 result;
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, begin, end - begin);
    SHA256_Final(reinterpret_cast<unsigned char*>(&result), &ctx);

    return result;
}

#endif // BITCOIN_HASH_H
