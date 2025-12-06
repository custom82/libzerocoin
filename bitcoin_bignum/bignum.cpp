#include "bitcoin_bignum/bignum.h"
#include <openssl/bn.h>

// Costruttori mancanti
CBigNum::CBigNum(signed char n) {
    bn = BN_new();
    if (n >= 0) setulong(n); else setint64(n);
}

CBigNum::CBigNum(short n) {
    bn = BN_new();
    if (n >= 0) setulong(n); else setint64(n);
}

CBigNum::CBigNum(int n) {
    bn = BN_new();
    if (n >= 0) setulong(n); else setint64(n);
}

CBigNum::CBigNum(long n) {
    bn = BN_new();
    if (n >= 0) setulong(n); else setint64(n);
}

CBigNum::CBigNum(int64 n) {
    bn = BN_new();
    setint64(n);
}

CBigNum::CBigNum(unsigned char n) {
    bn = BN_new();
    setulong(n);
}

CBigNum::CBigNum(unsigned short n) {
    bn = BN_new();
    setulong(n);
}

CBigNum::CBigNum(unsigned int n) {
    bn = BN_new();
    setulong(n);
}

CBigNum::CBigNum(unsigned long n) {
    bn = BN_new();
    setulong(n);
}

CBigNum::CBigNum(uint64 n) {
    bn = BN_new();
    setuint64(n);
}

CBigNum::CBigNum(uint256 n) {
    bn = BN_new();
    setuint256(n);
}

// Override operatori di confronto
bool operator==(const CBigNum& a, const CBigNum& b) { 
    return (BN_cmp(a.bn, b.bn) == 0); 
}

bool operator!=(const CBigNum& a, const CBigNum& b) { 
    return (BN_cmp(a.bn, b.bn) != 0); 
}

bool operator<=(const CBigNum& a, const CBigNum& b) { 
    return (BN_cmp(a.bn, b.bn) <= 0); 
}

bool operator>=(const CBigNum& a, const CBigNum& b) { 
    return (BN_cmp(a.bn, b.bn) >= 0); 
}

bool operator<(const CBigNum& a, const CBigNum& b)  { 
    return (BN_cmp(a.bn, b.bn) < 0); 
}

bool operator>(const CBigNum& a, const CBigNum& b)  { 
    return (BN_cmp(a.bn, b.bn) > 0); 
}

// Funzioni statiche
CBigNum CBigNum::RandKBitBigum(uint32_t k){
    CBigNum ret;
    if(!BN_rand(ret.bn, k, -1, 0)){
        throw std::runtime_error("CBigNum:rand element : BN_rand failed");
    }
    return ret;
}
