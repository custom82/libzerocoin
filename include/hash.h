#ifndef HASH_H
#define HASH_H

#include "zerocoin_defs.h"
#include <string>
#include <vector>

namespace libzerocoin {

    // Hash function declarations
    uint256 Hash(const std::vector<unsigned char>& vch);
    uint256 Hash(const std::string& str);
    uint256 Hash(const CBigNum& bn);

} // namespace libzerocoin

#endif
