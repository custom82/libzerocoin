// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_UINT256_H
#define BITCOIN_UINT256_H

#include <climits>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <string>
#include <vector>
#include <stdexcept>
#include <type_traits>
#include <algorithm>

/** Template base class for fixed-sized opaque blobs. */
template<unsigned int BITS>
class base_blob
{
protected:
    static constexpr int WIDTH = BITS / 8;
    uint8_t data[WIDTH];
public:
    base_blob()
    {
        memset(data, 0, sizeof(data));
    }

    explicit base_blob(const std::vector<uint8_t>& vch)
    {
        assert(vch.size() == sizeof(data));
        memcpy(data, vch.data(), sizeof(data));
    }

    bool IsNull() const
    {
        for (int i = 0; i < WIDTH; i++)
            if (data[i] != 0)
                return false;
        return true;
    }

    void SetNull()
    {
        memset(data, 0, sizeof(data));
    }

    friend inline bool operator==(const base_blob& a, const base_blob& b)
    {
        return memcmp(a.data, b.data, sizeof(a.data)) == 0;
    }

    friend inline bool operator!=(const base_blob& a, const base_blob& b)
    {
        return memcmp(a.data, b.data, sizeof(a.data)) != 0;
    }

    friend inline bool operator<(const base_blob& a, const base_blob& b)
    {
        return memcmp(a.data, b.data, sizeof(a.data)) < 0;
    }

    std::string GetHex() const
    {
        char psz[sizeof(data) * 2 + 1];
        for (unsigned int i = 0; i < sizeof(data); i++)
            sprintf(psz + i * 2, "%02x", data[sizeof(data) - i - 1]);
        return std::string(psz, psz + sizeof(data) * 2);
    }

    void SetHex(const char* psz)
    {
        memset(data, 0, sizeof(data));

        // skip leading spaces
        while (isspace(static_cast<unsigned char>(*psz)))
            psz++;

        // skip 0x
        if (psz[0] == '0' && tolower(static_cast<unsigned char>(psz[1])) == 'x')
            psz += 2;

        // hex string to uint
        const char* pbegin = psz;
        while (::HexDigit(static_cast<unsigned char>(*psz)) != -1)
            psz++;
        psz--;
        uint8_t* p1 = reinterpret_cast<uint8_t*>(data);
        uint8_t* pend = p1 + WIDTH;
        while (psz >= pbegin && p1 < pend)
        {
            *p1 = static_cast<uint8_t>(::HexDigit(static_cast<unsigned char>(*psz--)));
            if (psz >= pbegin)
            {
                *p1 |= static_cast<uint8_t>(::HexDigit(static_cast<unsigned char>(*psz--)) << 4);
                p1++;
            }
        }
    }

    void SetHex(const std::string& str)
    {
        SetHex(str.c_str());
    }

    std::string ToString() const
    {
        return GetHex();
    }

    const uint8_t* begin() const
    {
        return &data[0];
    }

    const uint8_t* end() const
    {
        return &data[WIDTH];
    }

    uint8_t* begin()
    {
        return &data[0];
    }

    uint8_t* end()
    {
        return &data[WIDTH];
    }

    unsigned int size() const
    {
        return sizeof(data);
    }

    uint64_t GetUint64(int pos = 0) const
    {
        const uint8_t* ptr = data + pos * 8;
        return static_cast<uint64_t>(ptr[0]) | (static_cast<uint64_t>(ptr[1]) << 8) |
        (static_cast<uint64_t>(ptr[2]) << 16) | (static_cast<uint64_t>(ptr[3]) << 24) |
        (static_cast<uint64_t>(ptr[4]) << 32) | (static_cast<uint64_t>(ptr[5]) << 40) |
        (static_cast<uint64_t>(ptr[6]) << 48) | (static_cast<uint64_t>(ptr[7]) << 56);
    }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        s.write(reinterpret_cast<const char*>(data), sizeof(data));
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s.read(reinterpret_cast<char*>(data), sizeof(data));
    }
};

/** 160-bit opaque blob.
 * @note This type is called uint160 for historical reasons only. It is an opaque
 * blob of 160 bits and has no integer operations.
 */
class uint160 : public base_blob<160>
{
public:
    uint160() {}
    explicit uint160(const std::vector<uint8_t>& vch) : base_blob<160>(vch) {}

    static uint160 CreateFromHex(const std::string& hex)
    {
        uint160 r;
        r.SetHex(hex);
        return r;
    }
};

/** 256-bit opaque blob.
 * @note This type is called uint256 for historical reasons only. It is an
 * opaque blob of 256 bits and has no integer operations. Use arith_uint256 if
 * those are required.
 */
class uint256 : public base_blob<256>
{
public:
    uint256() {}
    explicit uint256(const std::vector<uint8_t>& vch) : base_blob<256>(vch) {}

    static uint256 CreateFromHex(const std::string& hex)
    {
        uint256 r;
        r.SetHex(hex);
        return r;
    }

    // Static factory methods for common values
    static uint256 Zero()
    {
        uint256 r;
        r.SetNull();
        return r;
    }

    static uint256 One()
    {
        uint256 r;
        r.data[31] = 1;
        return r;
    }

    // Comparison operators
    bool operator!() const { return IsNull(); }

    // Arithmetic operations (limited set)
    uint256& operator<<=(unsigned int shift);
    uint256& operator>>=(unsigned int shift);

    // Get as bytes (little-endian)
    std::vector<uint8_t> GetBytes() const
    {
        return std::vector<uint8_t>(begin(), end());
    }

    // Get as bytes (big-endian)
    std::vector<uint8_t> GetBytesBE() const
    {
        std::vector<uint8_t> result(begin(), end());
        std::reverse(result.begin(), result.end());
        return result;
    }

    // Create from big-endian bytes
    static uint256 FromBytesBE(const std::vector<uint8_t>& bytes)
    {
        if (bytes.size() != 32) {
            throw std::length_error("uint256: invalid byte length");
        }
        std::vector<uint8_t> reversed(bytes.rbegin(), bytes.rend());
        return uint256(reversed);
    }

    // Create from little-endian bytes
    static uint256 FromBytesLE(const std::vector<uint8_t>& bytes)
    {
        if (bytes.size() != 32) {
            throw std::length_error("uint256: invalid byte length");
        }
        return uint256(bytes);
    }
};

// Forward declarations for template operators
template<unsigned int BITS>
base_blob<BITS> operator<<(const base_blob<BITS>& a, unsigned int shift);

template<unsigned int BITS>
base_blob<BITS> operator>>(const base_blob<BITS>& a, unsigned int shift);

// Implementation
template<unsigned int BITS>
base_blob<BITS>& base_blob<BITS>::operator<<=(unsigned int shift)
{
    base_blob<BITS> a(*this);
    for (unsigned int i = 0; i < BITS/8; i++)
        data[i] = 0;
    int k = shift / 8;
    shift = shift % 8;
    for (unsigned int i = 0; i < BITS/8; i++)
    {
        if (i+k+1 < BITS/8 && shift != 0)
            data[i+k+1] |= (a.data[i] >> (8-shift));
        if (i+k < BITS/8)
            data[i+k] |= (a.data[i] << shift);
    }
    return *this;
}

template<unsigned int BITS>
base_blob<BITS>& base_blob<BITS>::operator>>=(unsigned int shift)
{
    base_blob<BITS> a(*this);
    for (unsigned int i = 0; i < BITS/8; i++)
        data[i] = 0;
    int k = shift / 8;
    shift = shift % 8;
    for (unsigned int i = 0; i < BITS/8; i++)
    {
        if (i-k-1 >= 0 && shift != 0)
            data[i-k-1] |= (a.data[i] << (8-shift));
        if (i-k >= 0)
            data[i-k] |= (a.data[i] >> shift);
    }
    return *this;
}

template<unsigned int BITS>
base_blob<BITS> operator<<(const base_blob<BITS>& a, unsigned int shift)
{
    base_blob<BITS> r = a;
    r <<= shift;
    return r;
}

template<unsigned int BITS>
base_blob<BITS> operator>>(const base_blob<BITS>& a, unsigned int shift)
{
    base_blob<BITS> r = a;
    r >>= shift;
    return r;
}

// Specializations for uint256
inline uint256& uint256::operator<<=(unsigned int shift)
{
    return base_blob<256>::operator<<=(shift);
}

inline uint256& uint256::operator>>=(unsigned int shift)
{
    return base_blob<256>::operator>>=(shift);
}

// Hash function for use in unordered containers
namespace std
{
    template<unsigned int BITS>
    struct hash<base_blob<BITS>>
    {
        size_t operator()(const base_blob<BITS>& b) const
        {
            return *(reinterpret_cast<const size_t*>(b.begin()));
        }
    };

    template<>
    struct hash<uint160>
    {
        size_t operator()(const uint160& b) const
        {
            return *(reinterpret_cast<const size_t*>(b.begin()));
        }
    };

    template<>
    struct hash<uint256>
    {
        size_t operator()(const uint256& b) const
        {
            return *(reinterpret_cast<const size_t*>(b.begin()));
        }
    };
}

// Helper function for hex digit conversion
namespace
{
    inline int HexDigit(char c)
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    }
}

#endif
