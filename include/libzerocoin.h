#ifndef LIBZEROCOIN_H
#define LIBZEROCOIN_H

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <memory>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <sstream>
#include <iostream>

namespace libzerocoin {

    // ============================================================================
    // Basic Types and Constants
    // ============================================================================

    class uint256;
    class CBigNum;
    class IntegerGroupParams;
    class ZerocoinParams;
    class Accumulator;
    class AccumulatorWitness;
    class AccumulatorProofOfKnowledge;
    class SerialNumberSignatureOfKnowledge;
    class CommitmentProofOfKnowledge;
    class Proof;
    class PublicCoin;
    class PrivateCoin;
    class Commitment;
    class CoinSpend;
    class SpendMetaData;

    // Security levels
    enum SecurityLevel {
        SECURITY_LEVEL_80 = 80,
        SECURITY_LEVEL_128 = 128,
        SECURITY_LEVEL_256 = 256
    };

    // Coin denominations
    enum CoinDenomination {
        ZQ_ERROR = 0,
        ZQ_ONE = 1,
        ZQ_FIVE = 5,
        ZQ_TEN = 10,
        ZQ_FIFTY = 50,
        ZQ_ONE_HUNDRED = 100,
        ZQ_FIVE_HUNDRED = 500,
        ZQ_ONE_THOUSAND = 1000,
        ZQ_FIVE_THOUSAND = 5000
    };

    // Convert denomination to string
    std::string DenominationToString(CoinDenomination denomination);
    CoinDenomination StringToDenomination(const std::string& str);

    // ============================================================================
    // Serialization Support
    // ============================================================================

    class CDataStream {
    private:
        std::vector<unsigned char> vch;
        size_t nReadPos;

    public:
        CDataStream() : nReadPos(0) {}

        template<typename T>
        CDataStream& operator<<(const T& obj) {
            // Serialize obj into vch
            const unsigned char* p = (const unsigned char*)&obj;
            vch.insert(vch.end(), p, p + sizeof(T));
            return *this;
        }

        template<typename T>
        CDataStream& operator>>(T& obj) {
            // Deserialize obj from vch
            if (nReadPos + sizeof(T) > vch.size()) {
                throw std::runtime_error("CDataStream::operator>>: out of data");
            }
            memcpy(&obj, &vch[nReadPos], sizeof(T));
            nReadPos += sizeof(T);
            return *this;
        }

        void write(const char* pch, size_t nSize) {
            vch.insert(vch.end(), pch, pch + nSize);
        }

        void read(char* pch, size_t nSize) {
            if (nReadPos + nSize > vch.size()) {
                throw std::runtime_error("CDataStream::read: out of data");
            }
            memcpy(pch, &vch[nReadPos], nSize);
            nReadPos += nSize;
        }

        void clear() { vch.clear(); nReadPos = 0; }
        size_t size() const { return vch.size(); }
        bool empty() const { return vch.empty(); }
        const std::vector<unsigned char>& getvch() const { return vch; }
    };

    // Serialization macros (simplified from original)
    #define READWRITE(obj) (ser_action.ForRead() ? ser_action.stream >> obj : ser_action.stream << obj)
    #define READWRITECOMPRESS(obj) READWRITE(obj)

    class CSerializeData : public std::vector<unsigned char> {
    public:
        CSerializeData() {}
        CSerializeData(size_t nSize) : std::vector<unsigned char>(nSize) {}
    };

    // Serialization action
    enum CSerAction {
        SER_NETWORK = 1,
        SER_DISK = 2
    };

    // ============================================================================
    // uint256 - 256-bit hash (Enhanced)
    // ============================================================================

    class uint256 {
    private:
        unsigned char data[32];

    public:
        uint256() { memset(data, 0, sizeof(data)); }

        uint256(uint64_t b) {
            memset(data, 0, sizeof(data));
            data[24] = (b >> 56) & 0xff;
            data[25] = (b >> 48) & 0xff;
            data[26] = (b >> 40) & 0xff;
            data[27] = (b >> 32) & 0xff;
            data[28] = (b >> 24) & 0xff;
            data[29] = (b >> 16) & 0xff;
            data[30] = (b >> 8) & 0xff;
            data[31] = b & 0xff;
        }

        uint256(const std::string& str) {
            fromHex(str);
        }

        uint256(const std::vector<unsigned char>& vch) {
            if (vch.size() == 32) {
                memcpy(data, vch.data(), 32);
            } else {
                memset(data, 0, sizeof(data));
            }
        }

        bool IsNull() const {
            for (int i = 0; i < 32; i++) {
                if (data[i] != 0) return false;
            }
            return true;
        }

        void SetNull() {
            memset(data, 0, sizeof(data));
        }

        bool operator==(const uint256& b) const {
            return memcmp(data, b.data, 32) == 0;
        }

        bool operator!=(const uint256& b) const {
            return memcmp(data, b.data, 32) != 0;
        }

        bool operator<(const uint256& b) const {
            return memcmp(data, b.data, 32) < 0;
        }

        const unsigned char* begin() const { return data; }
        const unsigned char* end() const { return data + 32; }
        unsigned char* begin() { return data; }
        unsigned char* end() { return data + 32; }

        unsigned char& operator[](size_t pos) { return data[pos]; }
        const unsigned char& operator[](size_t pos) const { return data[pos]; }

        std::string ToString() const {
            static const char* hexmap = "0123456789abcdef";
            std::string s(64, ' ');
            for (int i = 0; i < 32; i++) {
                s[2*i] = hexmap[(data[i] & 0xF0) >> 4];
                s[2*i+1] = hexmap[data[i] & 0x0F];
            }
            return s;
        }

        void fromHex(const std::string& hex) {
            if (hex.size() != 64) {
                SetNull();
                return;
            }

            for (size_t i = 0; i < 32; i++) {
                std::string byte = hex.substr(i*2, 2);
                data[i] = (unsigned char)strtol(byte.c_str(), nullptr, 16);
            }
        }

        uint256 reverse() const {
            uint256 result;
            for (int i = 0; i < 32; i++) {
                result.data[i] = data[31 - i];
            }
            return result;
        }

        // Serialization support
        template<typename Stream>
        void Serialize(Stream& s) const {
            s.write((char*)data, 32);
        }

        template<typename Stream>
        void Unserialize(Stream& s) {
            s.read((char*)data, 32);
        }
    };

    // ============================================================================
    // CBigNum - Enhanced with OpenSSL 3.5 compatibility
    // ============================================================================

    class CBigNum {
    private:
        BIGNUM* bignum;
        static BN_CTX* ctx;

        // OpenSSL 3.5 EVP-based RSA for prime generation
        static EVP_PKEY* generateRSAKey(int bits);
        static BIGNUM* extractRSA_N(EVP_PKEY* pkey);

    public:
        // Constructors
        CBigNum();
        CBigNum(const CBigNum& b);
        explicit CBigNum(int n);
        explicit CBigNum(long n);
        explicit CBigNum(long long n);
        explicit CBigNum(unsigned int n);
        explicit CBigNum(unsigned long n);
        explicit CBigNum(unsigned long long n);
        explicit CBigNum(const std::vector<unsigned char>& vch);
        explicit CBigNum(const std::string& str);
        ~CBigNum();

        // Assignment
        CBigNum& operator=(const CBigNum& b);
        CBigNum& operator=(long long n);

        // Arithmetic operators
        CBigNum operator+(const CBigNum& b) const;
        CBigNum operator-(const CBigNum& b) const;
        CBigNum operator*(const CBigNum& b) const;
        CBigNum operator/(const CBigNum& b) const;
        CBigNum operator%(const CBigNum& b) const;

        CBigNum& operator+=(const CBigNum& b);
        CBigNum& operator-=(const CBigNum& b);
        CBigNum& operator*=(const CBigNum& b);
        CBigNum& operator/=(const CBigNum& b);
        CBigNum& operator%=(const CBigNum& b);

        // Unary operators
        CBigNum operator-() const;
        CBigNum operator++(int); // postfix
        CBigNum& operator++();    // prefix
        CBigNum operator--(int); // postfix
        CBigNum& operator--();    // prefix

        // Comparison operators
        friend bool operator==(const CBigNum& a, const CBigNum& b);
        friend bool operator!=(const CBigNum& a, const CBigNum& b);
        friend bool operator<=(const CBigNum& a, const CBigNum& b);
        friend bool operator>=(const CBigNum& a, const CBigNum& b);
        friend bool operator<(const CBigNum& a, const CBigNum& b);
        friend bool operator>(const CBigNum& a, const CBigNum& b);

        // Bitwise operators
        CBigNum operator<<(unsigned int shift) const;
        CBigNum operator>>(unsigned int shift) const;
        CBigNum& operator<<=(unsigned int shift);
        CBigNum& operator>>=(unsigned int shift);

        // Modular arithmetic
        CBigNum modExp(const CBigNum& e, const CBigNum& m) const;
        CBigNum modInverse(const CBigNum& m) const;
        CBigNum gcd(const CBigNum& b) const;

        // Cryptographic operations
        static CBigNum generatePrime(unsigned int numBits, bool safe = false);
        static CBigNum generateStrongPrime(unsigned int numBits, const CBigNum& aux = CBigNum(0));
        static CBigNum randBignum(const CBigNum& range);
        static CBigNum randBignum(const CBigNum& min, const CBigNum& max);
        static CBigNum randKBitBignum(unsigned int k);

        // Hash functions
        CBigNum sha256() const;
        CBigNum sha1() const;
        CBigNum ripemd160() const;

        // Conversion methods
        void setvch(const std::vector<unsigned char>& vch);
        std::vector<unsigned char> getvch() const;
        void setHex(const std::string& str);
        std::string getHex() const;
        std::string ToString(int nBase = 10) const;

        // Utility methods
        unsigned int bitSize() const;
        unsigned int byteSize() const;
        bool isPrime(int checks = 20) const;
        bool isOdd() const;
        bool isEven() const;
        bool isZero() const;
        bool isOne() const;
        bool isNegative() const;
        void setNegative(bool negative);
        CBigNum abs() const;

        // Access to internal BIGNUM
        const BIGNUM* getBN() const { return bignum; }
        BIGNUM* getBN() { return bignum; }

        // Serialization
        template<typename Stream>
        void Serialize(Stream& s) const {
            std::vector<unsigned char> vch = getvch();
            unsigned int nSize = vch.size();
            s.write((char*)&nSize, sizeof(nSize));
            if (nSize > 0) {
                s.write((char*)&vch[0], nSize);
            }
        }

        template<typename Stream>
        void Unserialize(Stream& s) {
            unsigned int nSize;
            s.read((char*)&nSize, sizeof(nSize));
            if (nSize > 0) {
                std::vector<unsigned char> vch(nSize);
                s.read((char*)&vch[0], nSize);
                setvch(vch);
            } else {
                *this = 0;
            }
        }

        // Static initialization
        static void init();
        static void cleanup();
    };

    // Comparison operators (must be in header for template friend)
    bool operator==(const CBigNum& a, const CBigNum& b);
    bool operator!=(const CBigNum& a, const CBigNum& b);
    bool operator<=(const CBigNum& a, const CBigNum& b);
    bool operator>=(const CBigNum& a, const CBigNum& b);
    bool operator<(const CBigNum& a, const CBigNum& b);
    bool operator>(const CBigNum& a, const CBigNum& b);

    // ============================================================================
    // Hash Functions (Enhanced)
    // ============================================================================

    uint256 Hash(const std::vector<unsigned char>& vch);
    uint256 Hash(const std::string& str);
    uint256 Hash(const uint256& hash);
    uint256 HashSHA256(const std::vector<unsigned char>& vch);
    uint256 HashSHA1(const std::vector<unsigned char>& vch);
    uint256 HashRIPEMD160(const std::vector<unsigned char>& vch);
    uint256 HashSHA256D(const std::vector<unsigned char>& vch); // Double SHA256

    // HMAC
    std::vector<unsigned char> HMAC_SHA256(const std::vector<unsigned char>& key,
                                           const std::vector<unsigned char>& message);

    // ============================================================================
    // IntegerGroupParams (Enhanced from original)
    // ============================================================================

    class IntegerGroupParams {
    public:
        CBigNum g;
        CBigNum h;
        CBigNum p;
        CBigNum q;
        CBigNum groupOrder;

        IntegerGroupParams();
        ~IntegerGroupParams() = default;

        // Generate random element in the group
        CBigNum randomElement() const;

        // Validate parameters
        bool validate() const;

        // Check if element is in group
        bool isElement(const CBigNum& element) const;

        // Serialization
        template<typename Stream>
        void Serialize(Stream& s) const {
            g.Serialize(s);
            h.Serialize(s);
            p.Serialize(s);
            q.Serialize(s);
            groupOrder.Serialize(s);
        }

        template<typename Stream>
        void Unserialize(Stream& s) {
            g.Unserialize(s);
            h.Unserialize(s);
            p.Unserialize(s);
            q.Unserialize(s);
            groupOrder.Unserialize(s);
        }
    };

    // ============================================================================
    // ZerocoinParams (Enhanced from original)
    // ============================================================================

    class ZerocoinParams {
    public:
        IntegerGroupParams coinCommitmentGroup;
        IntegerGroupParams serialNumberSoKCommitmentGroup;
        IntegerGroupParams accumulatorParams;

        uint32_t accumulatorParamsMinPrimeLength;
        uint32_t ZK_iterations;
        uint32_t securityLevel;

        // Original constructors
        ZerocoinParams();
        ZerocoinParams(CBigNum N, uint32_t securityLevel = 80);
        ~ZerocoinParams() = default;

        // Validate all parameters
        bool validate() const;

        // Get denomination values
        static CBigNum getCoinValue(CoinDenomination denomination);

        // Serialization
        template<typename Stream>
        void Serialize(Stream& s) const {
            coinCommitmentGroup.Serialize(s);
            serialNumberSoKCommitmentGroup.Serialize(s);
            accumulatorParams.Serialize(s);
            s.write((char*)&accumulatorParamsMinPrimeLength, sizeof(accumulatorParamsMinPrimeLength));
            s.write((char*)&ZK_iterations, sizeof(ZK_iterations));
            s.write((char*)&securityLevel, sizeof(securityLevel));
        }

        template<typename Stream>
        void Unserialize(Stream& s) {
            coinCommitmentGroup.Unserialize(s);
            serialNumberSoKCommitmentGroup.Unserialize(s);
            accumulatorParams.Unserialize(s);
            s.read((char*)&accumulatorParamsMinPrimeLength, sizeof(accumulatorParamsMinPrimeLength));
            s.read((char*)&ZK_iterations, sizeof(ZK_iterations));
            s.read((char*)&securityLevel, sizeof(securityLevel));
        }
    };

    // ============================================================================
    // Accumulator (Enhanced from original)
    // ============================================================================

    class Accumulator {
    private:
        const IntegerGroupParams* params;
        CBigNum value;

    public:
        Accumulator(const IntegerGroupParams* p, const CBigNum& val);
        ~Accumulator() = default;

        // Add element to accumulator
        void accumulate(const CBigNum& val);
        void Add(const CBigNum& val) { accumulate(val); } // Alias for compatibility

        // Get current value
        CBigNum getValue() const { return value; }
        const IntegerGroupParams* getParams() const { return params; }

        // Verify if value is in accumulator
        bool isMember(const CBigNum& val) const;

        // Serialization
        template<typename Stream>
        void Serialize(Stream& s) const {
            value.Serialize(s);
        }

        template<typename Stream>
        void Unserialize(Stream& s, const IntegerGroupParams* p) {
            params = p;
            value.Unserialize(s);
        }
    };

    // ============================================================================
    // AccumulatorWitness (Enhanced from original)
    // ============================================================================

    class AccumulatorWitness {
    private:
        const Accumulator* accumulator;
        CBigNum element;
        CBigNum witness;

    public:
        AccumulatorWitness(const Accumulator* acc, const CBigNum& elem);
        ~AccumulatorWitness() = default;

        // Add element and update witness
        void AddElement(const CBigNum& elem);

        // Verify witness
        bool Verify() const;

        // Get witness value
        CBigNum getValue() const { return witness; }

        // Get element
        CBigNum getElement() const { return element; }

        // Serialization
        template<typename Stream>
        void Serialize(Stream& s) const {
            element.Serialize(s);
            witness.Serialize(s);
        }

        template<typename Stream>
        void Unserialize(Stream& s, const Accumulator* acc) {
            accumulator = acc;
            element.Unserialize(s);
            witness.Unserialize(s);
        }
    };

    // Continuazione del file header...

    namespace libzerocoin {

        // ============================================================================
        // Proof Base Class (from original)
        // ============================================================================

        class Proof {
        public:
            virtual ~Proof() = default;

            // Verify the proof
            virtual bool Verify(const ZerocoinParams* params) const = 0;

            // Serialization
            virtual void Serialize(CDataStream& stream) const = 0;
            virtual void Unserialize(CDataStream& stream) = 0;

            // Get proof size in bytes
            virtual size_t GetSize() const = 0;
        };

        // ============================================================================
        // Commitment Proof of Knowledge (from original)
        // ============================================================================

        class CommitmentProofOfKnowledge : public Proof {
        private:
            CBigNum S;
            CBigNum A;
            CBigNum C;
            CBigNum v_response;
            CBigNum rA_response;
            CBigNum rB_response;

        public:
            CommitmentProofOfKnowledge() = default;
            CommitmentProofOfKnowledge(const IntegerGroupParams* params,
                                       const Commitment& commitment,
                                       const CBigNum& value);

            // Proof interface
            bool Verify(const ZerocoinParams* params) const override;
            void Serialize(CDataStream& stream) const override;
            void Unserialize(CDataStream& stream) override;
            size_t GetSize() const override;

            // Original methods
            bool Verify(const IntegerGroupParams* params,
                        const Commitment& commitment) const;

                        // Getters
                        const CBigNum& getS() const { return S; }
                        const CBigNum& getA() const { return A; }
                        const CBigNum& getC() const { return C; }

                        // Create a proof for a commitment
                        static std::unique_ptr<CommitmentProofOfKnowledge> Create(
                            const IntegerGroupParams* params,
                            const Commitment& commitment,
                            const CBigNum& value,
                            const CBigNum& randomness);
        };

        // ============================================================================
        // Accumulator Proof of Knowledge (from original)
        // ============================================================================

        class AccumulatorProofOfKnowledge : public Proof {
        private:
            CBigNum C_e;
            CBigNum C_u;
            CBigNum C_r;
            CBigNum st_1;
            CBigNum st_2;
            CBigNum st_3;
            CBigNum t_1;
            CBigNum t_2;
            CBigNum t_3;
            CBigNum t_4;
            CBigNum s_alpha;
            CBigNum s_beta;
            CBigNum s_zeta;
            CBigNum s_sigma;
            CBigNum s_eta;
            CBigNum s_epsilon;
            CBigNum s_delta;
            CBigNum s_xi;
            CBigNum s_phi;
            CBigNum s_gamma;
            CBigNum s_psi;

        public:
            AccumulatorProofOfKnowledge() = default;

            // Original constructor from master branch
            AccumulatorProofOfKnowledge(const IntegerGroupParams* accumulatorParams,
                                        const IntegerGroupParams* commitmentParams,
                                        const Commitment& commitmentToCoin,
                                        const Accumulator& accumulator);

            // Proof interface
            bool Verify(const ZerocoinParams* params) const override;
            void Serialize(CDataStream& stream) const override;
            void Unserialize(CDataStream& stream) override;
            size_t GetSize() const override;

            // Original verification method
            bool Verify(const Accumulator& accumulator,
                        const Commitment& commitmentToCoin) const;

                        // Create proof
                        static std::unique_ptr<AccumulatorProofOfKnowledge> Create(
                            const IntegerGroupParams* accumulatorParams,
                            const IntegerGroupParams* commitmentParams,
                            const Commitment& commitmentToCoin,
                            const CBigNum& coinValue,
                            const CBigNum& coinRandomness,
                            const Accumulator& accumulator);
        };

        // ============================================================================
        // Serial Number Signature of Knowledge (from original)
        // ============================================================================

        class SerialNumberSignatureOfKnowledge : public Proof {
        private:
            CBigNum A_prime;
            CBigNum B_prime;
            CBigNum r_1;
            CBigNum r_2;
            CBigNum r_3;
            CBigNum m_1;
            CBigNum m_2;
            CBigNum m_3;
            CBigNum s_1;
            CBigNum s_2;
            CBigNum s_3;
            CBigNum t_1;
            CBigNum t_2;
            CBigNum t_3;
            CBigNum t_4;

        public:
            SerialNumberSignatureOfKnowledge() = default;

            // Original constructor from master branch
            SerialNumberSignatureOfKnowledge(const IntegerGroupParams* params,
                                             const CBigNum& coinSerialNumber,
                                             const CBigNum& valueOfCommitmentToCoin,
                                             const CBigNum& serialNumberSokCommitment,
                                             const CBigNum& randomness,
                                             const uint256& msghash);

            // Proof interface
            bool Verify(const ZerocoinParams* params) const override;
            void Serialize(CDataStream& stream) const override;
            void Unserialize(CDataStream& stream) override;
            size_t GetSize() const override;

            // Original verification method
            bool Verify(const CBigNum& coinSerialNumber,
                        const CBigNum& valueOfCommitmentToCoin,
                        const CBigNum& serialNumberSokCommitment,
                        const uint256& msghash) const;

                        // Create signature
                        static std::unique_ptr<SerialNumberSignatureOfKnowledge> Create(
                            const IntegerGroupParams* params,
                            const CBigNum& coinSerialNumber,
                            const CBigNum& valueOfCommitmentToCoin,
                            const CBigNum& serialNumberSokCommitment,
                            const CBigNum& randomness,
                            const uint256& msghash);
        };

        // ============================================================================
        // Coin Classes (Enhanced with original features)
        // ============================================================================

        class PublicCoin {
        private:
            const ZerocoinParams* params;
            CBigNum value;
            CoinDenomination denomination;

        public:
            PublicCoin() : params(nullptr), denomination(ZQ_ERROR) {}
            PublicCoin(const ZerocoinParams* p, const CBigNum& v, CoinDenomination d)
            : params(p), value(v), denomination(d) {}

            // Getters
            const CBigNum& getValue() const { return value; }
            CoinDenomination getDenomination() const { return denomination; }
            const ZerocoinParams* getParams() const { return params; }

            // Validation
            bool validate() const;

            // Comparison
            bool operator==(const PublicCoin& other) const;
            bool operator!=(const PublicCoin& other) const;
            bool operator<(const PublicCoin& other) const;

            // Hash
            uint256 getValueHash() const;

            // Serialization
            template<typename Stream>
            void Serialize(Stream& s) const {
                value.Serialize(s);
                uint32_t denom = (uint32_t)denomination;
                s.write((char*)&denom, sizeof(denom));
            }

            template<typename Stream>
            void Unserialize(Stream& s, const ZerocoinParams* p) {
                params = p;
                value.Unserialize(s);
                uint32_t denom;
                s.read((char*)&denom, sizeof(denom));
                denomination = (CoinDenomination)denom;
            }
        };

        class PrivateCoin {
        private:
            const ZerocoinParams* params;
            CBigNum serialNumber;
            CBigNum randomness;
            PublicCoin publicCoin;
            CoinDenomination denomination;
            uint8_t version;
            CBigNum v;

        public:
            // Constructors
            PrivateCoin(const ZerocoinParams* p, CoinDenomination d, uint8_t v = 1);

            // Getters
            const CBigNum& getSerialNumber() const { return serialNumber; }
            const CBigNum& getRandomness() const { return randomness; }
            const PublicCoin& getPublicCoin() const { return publicCoin; }
            CoinDenomination getDenomination() const { return denomination; }
            uint8_t getVersion() const { return version; }
            const CBigNum& getV() const { return v; }

            // Generate coin with proper cryptographic properties
            void generate();

            // Create commitment for this coin
            Commitment createCommitment() const;

            // Create serial number signature
            std::unique_ptr<SerialNumberSignatureOfKnowledge> createSerialNumberSignature(
                const uint256& msghash) const;

                // Validate coin
                bool validate() const;

                // Serialization
                template<typename Stream>
                void Serialize(Stream& s) const {
                    serialNumber.Serialize(s);
                    randomness.Serialize(s);
                    publicCoin.Serialize(s);
                    s.write((char*)&denomination, sizeof(denomination));
                    s.write((char*)&version, sizeof(version));
                    v.Serialize(s);
                }

                template<typename Stream>
                void Unserialize(Stream& s, const ZerocoinParams* p) {
                    params = p;
                    serialNumber.Unserialize(s);
                    randomness.Unserialize(s);
                    publicCoin.Unserialize(s, p);
                    s.read((char*)&denomination, sizeof(denomination));
                    s.read((char*)&version, sizeof(version));
                    v.Unserialize(s);
                }
        };

        // ============================================================================
        // Commitment (Enhanced)
        // ============================================================================

        class Commitment {
        private:
            const IntegerGroupParams* params;
            CBigNum commitment;
            CBigNum value;
            CBigNum randomness;

        public:
            Commitment() : params(nullptr) {}
            Commitment(const IntegerGroupParams* p, const CBigNum& val, const CBigNum& rand);

            // Getters
            CBigNum getCommitmentValue() const { return commitment; }
            const IntegerGroupParams* getParams() const { return params; }
            const CBigNum& getValue() const { return value; }
            const CBigNum& getRandomness() const { return randomness; }

            // Verification
            bool verify() const;

            // Comparison
            bool operator==(const Commitment& rhs) const;
            bool operator!=(const Commitment& rhs) const;

            // Create proof of knowledge for this commitment
            std::unique_ptr<CommitmentProofOfKnowledge> createProof(const CBigNum& val) const;

            // Serialization
            template<typename Stream>
            void Serialize(Stream& s) const {
                commitment.Serialize(s);
                value.Serialize(s);
                randomness.Serialize(s);
            }

            template<typename Stream>
            void Unserialize(Stream& s, const IntegerGroupParams* p) {
                params = p;
                commitment.Unserialize(s);
                value.Unserialize(s);
                randomness.Unserialize(s);
            }
        };

        // ============================================================================
        // CoinSpend (Enhanced with original verification)
        // ============================================================================

        class CoinSpend {
        private:
            const ZerocoinParams* params;
            CoinDenomination denomination;
            uint32_t accumulatorId;
            uint256 ptxHash;
            uint256 accumulatorBlockHash;
            CBigNum coinSerialNumber;
            CBigNum accumulatorValue;
            std::unique_ptr<AccumulatorProofOfKnowledge> accumulatorProof;
            std::unique_ptr<SerialNumberSignatureOfKnowledge> serialNumberSignature;
            unsigned char version;
            uint8_t* bytes;
            int32_t txVersion;
            SpendMetaData metaData;

        public:
            // Constructors
            CoinSpend() : params(nullptr), bytes(nullptr) {}
            CoinSpend(const ZerocoinParams* params,
                      const PrivateCoin& coin,
                      Accumulator& accumulator,
                      const uint32_t& checksum,
                      const AccumulatorWitness& witness,
                      const uint256& ptxHash,
                      const SpendMetaData& metaData = SpendMetaData());

            // Destructor
            ~CoinSpend();

            // Getters
            const CBigNum& getCoinSerialNumber() const { return coinSerialNumber; }
            const uint256& getTxOutHash() const { return ptxHash; }
            const uint256& getAccumulatorBlockHash() const { return accumulatorBlockHash; }
            uint32_t getAccumulatorId() const { return accumulatorId; }
            CoinDenomination getDenomination() const { return denomination; }
            unsigned char getVersion() const { return version; }
            const SpendMetaData& getMetaData() const { return metaData; }
            const CBigNum& getAccumulatorValue() const { return accumulatorValue; }

            // Verification methods from original
            bool Verify(const Accumulator& accumulator) const;
            bool HasValidSerial() const;
            bool HasValidSignature() const;
            CBigNum CalculateValidSerial() const;

            // Check if spend is valid
            bool Verify() const;

            // Signature verification
            bool VerifySignature() const;

            // Serialization
            template<typename Stream>
            void Serialize(Stream& s) const;

            template<typename Stream>
            void Unserialize(Stream& s, const ZerocoinParams* p);

            // Get the signature
            const SerialNumberSignatureOfKnowledge* getSerialNumberSignature() const {
                return serialNumberSignature.get();
            }

            // Get the accumulator proof
            const AccumulatorProofOfKnowledge* getAccumulatorProof() const {
                return accumulatorProof.get();
            }
        };

        // ============================================================================
        // SpendMetaData (Enhanced)
        // ============================================================================

        class SpendMetaData {
        private:
            uint256 accumulatorId;
            uint256 txHash;
            uint256 blockHash;
            uint32_t height;

        public:
            SpendMetaData() : height(0) {}
            SpendMetaData(uint256 accumulatorId, uint256 txHash,
                          uint256 blockHash = uint256(), uint32_t height = 0);

            // Getters
            const uint256& getAccumulatorId() const { return accumulatorId; }
            const uint256& getTxHash() const { return txHash; }
            const uint256& getBlockHash() const { return blockHash; }
            uint32_t getHeight() const { return height; }

            // Setters
            void setAccumulatorId(const uint256& id) { accumulatorId = id; }
            void setTxHash(const uint256& hash) { txHash = hash; }
            void setBlockHash(const uint256& hash) { blockHash = hash; }
            void setHeight(uint32_t h) { height = h; }

            // Serialization
            template<typename Stream>
            void Serialize(Stream& s) const {
                accumulatorId.Serialize(s);
                txHash.Serialize(s);
                blockHash.Serialize(s);
                s.write((char*)&height, sizeof(height));
            }

            template<typename Stream>
            void Unserialize(Stream& s) {
                accumulatorId.Unserialize(s);
                txHash.Unserialize(s);
                blockHash.Unserialize(s);
                s.read((char*)&height, sizeof(height));
            }
        };

        // ============================================================================
        // Parameter Generation (Complete from original)
        // ============================================================================

        class ParamsSoK {
        public:
            CBigNum n;
            uint32_t securityLevel;

            ParamsSoK() : securityLevel(80) {}
        };

        // Calculate integer group parameters (from original ParamGeneration.cpp)
        IntegerGroupParams* CalculateIntegerParams(IntegerGroupParams &result,
                                                   const CBigNum& N, const uint32_t securityLevel);

        // Calculate accumulator parameters
        IntegerGroupParams* CalculateAccumulatorParams(IntegerGroupParams &result,
                                                       const CBigNum& N,
                                                       uint32_t securityLevel);

        // Generate Zerocoin parameters from N
        ZerocoinParams* GenerateZerocoinParams(ZerocoinParams &result,
                                               const CBigNum& N,
                                               uint32_t securityLevel = 80);

        // Verify parameters
        bool VerifyZerocoinParams(const ZerocoinParams& params);

        // ============================================================================
        // Utility Functions for Proofs
        // ============================================================================

        // Generate random challenge for proofs
        CBigNum GenerateRandomChallenge(uint32_t securityLevel = 80);

        // Hash to prime function (used in proofs)
        CBigNum HashToPrime(const std::vector<unsigned char>& input,
                            uint32_t securityLevel = 80);

        // Generate random parameters for testing
        ZerocoinParams GenerateTestParams(uint32_t securityLevel = 80);

    } // namespace libzerocoin


#endif // LIBZEROCOIN_H
