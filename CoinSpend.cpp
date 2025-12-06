#include "CoinSpend.h"
#include "Accumulator.h"

namespace libzerocoin
{

	CoinSpend::CoinSpend(const ZerocoinParams* p, const PrivateCoin& coin, const CBigNum& value)
	{
		// Definisci il costruttore, usato da CoinSpend
	}

	const uint256 CoinSpend::signatureHash(const SpendMetaData& m) const
	{
		CHashWriter h(0, 0);
		h << m << serialCommitmentToCoinValue << accCommitmentToCoinValue;  // Corretto con operator<<
		return h.GetHash();
	}

} // namespace libzerocoin
