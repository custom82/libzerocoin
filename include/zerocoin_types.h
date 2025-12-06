#ifndef ZEROCOIN_TYPES_H
#define ZEROCOIN_TYPES_H

#include <vector>
#include <cstdint>

namespace libzerocoin {

    enum CoinDenomination {
        ZQ_ONE = 1,
        ZQ_FIVE = 5,
        ZQ_TEN = 10,
        ZQ_FIFTY = 50,
        ZQ_ONE_HUNDRED = 100,
        ZQ_FIVE_HUNDRED = 500,
        ZQ_ONE_THOUSAND = 1000,
        ZQ_FIVE_THOUSAND = 5000,
        ZQ_ERROR = 0
    };

} // namespace libzerocoin

#endif // ZEROCOIN_TYPES_H
