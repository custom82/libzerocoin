#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

#include <vector>
#include <cstdint>
#include <string>
#include <openssl/sha.h>

#include "uint256.h"
#include "serialize.h"

inline uint256 Hash(const unsigned char* begin, const unsigned char* end)
{
    uint256 result;
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, begin, end - begin);
    SHA256_Final((unsigned char*)&result, &ctx);

    return result;
}

template<typename T>
uint256 Hash(const T& v)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << v;
    return Hash((unsigned char*)&ss[0], (unsigned char*)&ss[0] + ss.size());
}

#endif // BITCOIN_HASH_H
