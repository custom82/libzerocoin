#ifndef BITCOIN_HASH_H
#define BITCOIN_HASH_H

#include <vector>
#include <cstdint>
#include <string>
#include "uint256.h"

class CHashWriter {
private:
    int nType;
    int nVersion;
    std::vector<unsigned char> buffer;

public:
    CHashWriter(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {}

    CHashWriter& write(const char* pch, size_t size) {
        buffer.insert(buffer.end(), pch, pch + size);
        return *this;
    }

    template<typename T>
    CHashWriter& operator<<(const T& obj) {
        // Serialize the object
        ::Serialize(*this, obj, nType, nVersion);
        return *this;
    }

    uint256 GetHash() const {
        uint256 result;
        SHA256(buffer.data(), buffer.size(), (unsigned char*)&result);
        return result;
    }

    size_t size() const { return buffer.size(); }
};

#endif // BITCOIN_HASH_H
