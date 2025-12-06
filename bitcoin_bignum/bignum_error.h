#ifndef BIGNUM_ERROR_H
#define BIGNUM_ERROR_H

#include <exception>

class bignum_error : public std::exception {
public:
    const char* what() const noexcept override {
        return "Bignum operation failed";
    }
};

#endif // BIGNUM_ERROR_H
