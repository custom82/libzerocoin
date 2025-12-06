#pragma once
#ifndef LIBZEROCOIN_TYPES_H
#define LIBZEROCOIN_TYPES_H

#include <stdexcept>
#include <string>

namespace libzerocoin {

static constexpr int ZEROCOIN_VERSION = 1;

class ZerocoinException : public std::runtime_error {
public:
    explicit ZerocoinException(const std::string& msg)
        : std::runtime_error(msg) {}
};

enum CoinDenomination : int {
    ZQ_LOVELACE = 1
};

}

#endif
