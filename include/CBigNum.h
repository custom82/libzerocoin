#ifndef CBIGNUM_H
#define CBIGNUM_H

#include <openssl/bn.h>
#include <string>

class CBigNum {
public:
    CBigNum() { BN_init(&num); }  // Inizializza BIGNUM
    ~CBigNum() { BN_free(&num); } // Libera la memoria di BIGNUM

    // Imposta un valore esadecimale per il numero
    void setHex(const std::string& hexStr) {
        BN_hex2bn(&num, hexStr.c_str());
    }

    // Ottieni il valore del numero in formato esadecimale
    std::string getHex() const {
        char* hex = BN_bn2hex(&num);
        std::string result(hex);
        OPENSSL_free(hex);  // Dealloca la memoria
        return result;
    }

    // Operazione di sottrazione tra due numeri
    CBigNum operator-(const CBigNum& other) const {
        CBigNum result;
        BN_sub(&result.num, &this->num, &other.num);  // Sottrazione in OpenSSL
        return result;
    }

    // Altri operatori come +, *, / possono essere aggiunti in modo simile
    CBigNum operator+(const CBigNum& other) const {
        CBigNum result;
        BN_add(&result.num, &this->num, &other.num);  // Somma in OpenSSL
        return result;
    }

    CBigNum operator*(const CBigNum& other) const {
        CBigNum result;
        BN_mul(&result.num, &this->num, &other.num, nullptr);  // Moltiplicazione in OpenSSL
        return result;
    }

    CBigNum operator/(const CBigNum& other) const {
        CBigNum result;
        BN_div(&result.num, nullptr, &this->num, &other.num, nullptr);  // Divisione in OpenSSL
        return result;
    }

    // Confronto per uguaglianza
    bool operator==(const CBigNum& other) const {
        return BN_cmp(&this->num, &other.num) == 0;  // Confronto in OpenSSL
    }

private:
    BIGNUM num;  // Numero di grandi dimensioni utilizzato da OpenSSL
};

#endif // CBIGNUM_H
