AC_INIT([libzerocoin], [1.0.0])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_PROG_CXX
AC_PROG_LIBTOOL

# Check for OpenSSL
AC_CHECK_LIB([crypto], [BN_new], [], [AC_MSG_ERROR([OpenSSL crypto library not found])])
AC_CHECK_HEADERS([openssl/bn.h])

# Check for Boost
AX_BOOST_BASE([1.53.0])
AX_BOOST_SYSTEM
AX_BOOST_FILESYSTEM

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
