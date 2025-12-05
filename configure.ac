#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([libzerocoin], [2.0.0], [])
AC_CONFIG_SRCDIR([Zerocoin.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

# Check for C++ compiler
AC_PROG_CXX
AC_LANG([C++])

# Check for pkg-config
PKG_PROG_PKG_CONFIG

# ============================================
# CHECK FOR MODERN DEPENDENCIES
# ============================================

# OpenSSL 3.5 (REQUIRED)
AC_MSG_CHECKING([for OpenSSL >= 3.0.0])
PKG_CHECK_MODULES([SSL], [openssl >= 3.0.0],
    [
        AC_SUBST([SSL_CFLAGS])
        AC_SUBST([SSL_LIBS])
        SSL_CFLAGS="$SSL_CFLAGS -DOPENSSL_API_COMPAT=0x30000000L"
        AC_DEFINE([HAVE_OPENSSL3], [1], [Define if using OpenSSL 3.x])
        AC_MSG_RESULT([yes])
    ],
    [
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([OpenSSL >= 3.0.0 is required])
    ])

# GMP 6.3.0 (REQUIRED)
AC_MSG_CHECKING([for GMP >= 6.3.0])
PKG_CHECK_MODULES([GMP], [gmp >= 6.3.0],
    [
        AC_SUBST([GMP_CFLAGS])
        AC_SUBST([GMP_LIBS])
        AC_DEFINE([HAVE_GMP], [1], [Define if using GMP])
        AC_MSG_RESULT([yes])
    ],
    [
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([GMP >= 6.3.0 is required])
    ])

# Boost 1.88 (REQUIRED)
AC_MSG_CHECKING([for Boost >= 1.88.0])
AX_BOOST_BASE([1.88.0],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no])
     AC_MSG_ERROR([Boost >= 1.88.0 is required])])

AX_BOOST_SYSTEM
AX_BOOST_FILESYSTEM
AX_BOOST_PROGRAM_OPTIONS

# Check for C++11 support
AC_MSG_CHECKING([for C++11 support])
AX_CXX_COMPILE_STDCXX([11], [noext], [mandatory])
AC_MSG_RESULT([yes])

# Check for required headers
AC_CHECK_HEADERS([openssl/rsa.h openssl/bn.h openssl/sha.h openssl/aes.h openssl/evp.h openssl/provider.h])

# Output files
AC_CONFIG_FILES([Makefile
                 zerocoin.pc])
AC_OUTPUT

echo ""
echo "libzerocoin configured with:"
echo "  OpenSSL: >= 3.0.0"
echo "  GMP:     >= 6.3.0"
echo "  Boost:   >= 1.88.0"
echo ""
