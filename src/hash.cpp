#include "hash.h"
#include <openssl/sha.h>
#include <vector>

// Simple hash implementation
uint256 Hash(const std::vector<unsigned char>& vch) {
    uint256 result;
    SHA256(vch.data(), vch.size(), result.data());
    return result;
}

uint256 Hash(const std::string& str) {
    uint256 result;
    SHA256((const unsigned char*)str.c_str(), str.size(), result.data());
    return result;
}

uint256 Hash(const CBigNum& bn) {
    std::vector<unsigned char> vch = bn.getvch();
    return Hash(vch);
}
