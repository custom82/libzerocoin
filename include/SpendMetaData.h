#ifndef SPENDMETADATA_H
#define SPENDMETADATA_H

#include "uint256.h"

namespace libzerocoin {

	class SpendMetaData {
	private:
		uint256 accumulatorId;
		uint256 txHash;

	public:
		SpendMetaData() = default;
		SpendMetaData(uint256 accumulatorId, uint256 txHash);
		~SpendMetaData() = default;

		const uint256& getAccumulatorId() const { return accumulatorId; }
		const uint256& getTxHash() const { return txHash; }

		void setAccumulatorId(const uint256& id) { accumulatorId = id; }
		void setTxHash(const uint256& hash) { txHash = hash; }
	};

} // namespace libzerocoin

#endif // SPENDMETADATA_H
