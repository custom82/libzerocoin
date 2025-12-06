#include "SpendMetaData.h"

namespace libzerocoin {

    SpendMetaData::SpendMetaData(uint256 accumulatorId, uint256 txHash)
    : accumulatorId(accumulatorId), txHash(txHash) {
    }

} // namespace libzerocoin
