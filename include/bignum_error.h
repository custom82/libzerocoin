#ifndef BIGNUM_ERROR_H
#define BIGNUM_ERROR_H

#include <stdexcept>
#include <string>

class bignum_error : public std::runtime_error {
public:
    explicit bignum_error(const std::string& str) : std::runtime_error(str) {}
};

#endif
