ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libzerocoin.la

libzerocoin_la_SOURCES = \
    Accumulator.cpp \
    AccumulatorProofOfKnowledge.cpp \
    Coin.cpp \
    CoinSpend.cpp \
    Commitment.cpp \
    Denominations.cpp \
    ParamGeneration.cpp \
    Params.cpp \
    SerialNumberSignatureOfKnowledge.cpp \
    SpendMetaData.cpp \
    Zerocoin.cpp
    # NON aggiungere openssl_compat.cpp

libzerocoin_la_CPPFLAGS = \
    $(SSL_CFLAGS) \
    $(GMP_CFLAGS) \
    $(BOOST_CPPFLAGS) \
    -I$(srcdir)/bitcoin_bignum \
    -DOPENSSL_API_COMPAT=0x30000000L

libzerocoin_la_LDFLAGS = -no-undefined -version-info 4:0:0
libzerocoin_la_LIBADD = $(SSL_LIBS) $(GMP_LIBS)

# ... resto del file invariato ...
