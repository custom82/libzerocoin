#ifndef LIBZEROCOIN_SERIALNUM_SIGNATURE_OF_KNOWLEDGE_H
#define LIBZEROCOIN_SERIALNUM_SIGNATURE_OF_KNOWLEDGE_H

#include "src/serialize_stub.h"
#include "src/zerocoin_types.h"
#include "bitcoin_bignum/bignum.h"
#include "Params.h"
#include "Coin.h"

namespace libzerocoin {

	class SerialNumberSignatureOfKnowledge
	{
	private:
		const ZerocoinParams* params;
		CBigNum s_notprime;
		CBigNum sprime;

	public:
		SerialNumberSignatureOfKnowledge(
			const ZerocoinParams* p,
			const PublicCoin& coin,
			const CBigNum& serial);

		bool Verify(const CBigNum& serial) const;

		// FIX: versione corretta e unica della SerializationOp
		template <typename Stream, typename Operation>
		inline void SerializationOp(Stream& s, Operation ser_action)
		{
			READWRITE(s_notprime);
			READWRITE(sprime);
		}

		ADD_SERIALIZE_METHODS;
	};

} // namespace libzerocoin

#endif // LIBZEROCOIN_SERIALNUM_SIGNATURE_OF_KNOWLEDGE_H
