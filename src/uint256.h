// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WISPR_UINT256_H
#define WISPR_UINT256_H

#include <assert.h>
#include <cstring>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <vector>
#include <crypto/common.h>

/** Template base class for unsigned big integers. */
template <unsigned int BITS>
class base_blob
{
protected:
    enum { WIDTH = BITS / 32 };
//    uint8_t data[WIDTH];
    uint32_t pn[WIDTH];

public:
    base_blob()
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = 0;
    }

    base_blob(const base_blob& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = b.pn[i];
    }
    inline int Compare(const base_blob& other) const { return memcmp(pn, other.pn, sizeof(pn)); }


    bool IsNull() const
    {
        for (int i = 0; i < WIDTH; i++)
            if (pn[i] != 0)
                return false;
        return true;
    }

    void SetNull()
    {
        memset(pn, 0, sizeof(pn));
    }


    base_blob& operator=(const base_blob& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = b.pn[i];
        return *this;
    }

    base_blob(uint64_t b)
    {
        pn[0] = (unsigned int)b;
        pn[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < WIDTH; i++)
            pn[i] = 0;
    }

    explicit base_blob(const std::string& str);
    explicit base_blob(const std::vector<unsigned char>& vch);
    explicit base_blob(const uint32_t *p, size_t l);

    bool operator!() const
    {
        for (int i = 0; i < WIDTH; i++)
            if (pn[i] != 0)
                return false;
        return true;
    }

    const base_blob operator~() const
    {
        base_blob ret;
        for (int i = 0; i < WIDTH; i++)
            ret.pn[i] = ~pn[i];
        return ret;
    }

    const base_blob operator-() const
    {
        base_blob ret;
        for (int i = 0; i < WIDTH; i++)
            ret.pn[i] = ~pn[i];
        ret++;
        return ret;
    }

    double getdouble() const;

    base_blob& operator=(uint64_t b)
    {
        pn[0] = (unsigned int)b;
        pn[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < WIDTH; i++)
            pn[i] = 0;
        return *this;
    }

    base_blob& operator^=(const base_blob& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] ^= b.pn[i];
        return *this;
    }

    base_blob& operator&=(const base_blob& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] &= b.pn[i];
        return *this;
    }

    base_blob& operator|=(const base_blob& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] |= b.pn[i];
        return *this;
    }

    base_blob& operator^=(uint64_t b)
    {
        pn[0] ^= (unsigned int)b;
        pn[1] ^= (unsigned int)(b >> 32);
        return *this;
    }

    base_blob& operator|=(uint64_t b)
    {
        pn[0] |= (unsigned int)b;
        pn[1] |= (unsigned int)(b >> 32);
        return *this;
    }

    base_blob& operator<<=(unsigned int shift);
    base_blob& operator>>=(unsigned int shift);

    base_blob& operator+=(const base_blob& b)
    {
        uint64_t carry = 0;
        for (int i = 0; i < WIDTH; i++) {
            uint64_t n = carry + pn[i] + b.pn[i];
            pn[i] = n & 0xffffffff;
            carry = n >> 32;
        }
        return *this;
    }

    base_blob& operator-=(const base_blob& b)
    {
        *this += -b;
        return *this;
    }

    base_blob& operator+=(uint64_t b64)
    {
        base_blob b;
        b = b64;
        *this += b;
        return *this;
    }

    base_blob& operator-=(uint64_t b64)
    {
        base_blob b;
        b = b64;
        *this += -b;
        return *this;
    }

    base_blob& operator*=(uint32_t b32);
    base_blob& operator*=(const base_blob& b);
    base_blob& operator/=(const base_blob& b);

    base_blob& operator++()
    {
        // prefix operator
        int i = 0;
        while (++pn[i] == 0 && i < WIDTH - 1)
            i++;
        return *this;
    }

    const base_blob operator++(int)
    {
        // postfix operator
        const base_blob ret = *this;
        ++(*this);
        return ret;
    }

    base_blob& operator--()
    {
        // prefix operator
        int i = 0;
        while (--pn[i] == (uint32_t)-1 && i < WIDTH - 1)
            i++;
        return *this;
    }

    const base_blob operator--(int)
    {
        // postfix operator
        const base_blob ret = *this;
        --(*this);
        return ret;
    }

    int CompareTo(const base_blob& b) const;
    bool EqualTo(uint64_t b) const;

    friend inline const base_blob operator+(const base_blob& a, const base_blob& b) { return base_blob(a) += b; }
    friend inline const base_blob operator-(const base_blob& a, const base_blob& b) { return base_blob(a) -= b; }
    friend inline const base_blob operator*(const base_blob& a, const base_blob& b) { return base_blob(a) *= b; }
    friend inline const base_blob operator/(const base_blob& a, const base_blob& b) { return base_blob(a) /= b; }
    friend inline const base_blob operator|(const base_blob& a, const base_blob& b) { return base_blob(a) |= b; }
    friend inline const base_blob operator&(const base_blob& a, const base_blob& b) { return base_blob(a) &= b; }
    friend inline const base_blob operator^(const base_blob& a, const base_blob& b) { return base_blob(a) ^= b; }
    friend inline const base_blob operator>>(const base_blob& a, int shift) { return base_blob(a) >>= shift; }
    friend inline const base_blob operator<<(const base_blob& a, int shift) { return base_blob(a) <<= shift; }
    friend inline const base_blob operator*(const base_blob& a, uint32_t b) { return base_blob(a) *= b; }
    friend inline bool operator==(const base_blob& a, const base_blob& b) { return memcmp(a.pn, b.pn, sizeof(a.pn)) == 0; }
    friend inline bool operator!=(const base_blob& a, const base_blob& b) { return memcmp(a.pn, b.pn, sizeof(a.pn)) != 0; }
    friend inline bool operator>(const base_blob& a, const base_blob& b) { return a.CompareTo(b) > 0; }
    friend inline bool operator<(const base_blob& a, const base_blob& b) { return a.CompareTo(b) < 0; }
    friend inline bool operator>=(const base_blob& a, const base_blob& b) { return a.CompareTo(b) >= 0; }
    friend inline bool operator<=(const base_blob& a, const base_blob& b) { return a.CompareTo(b) <= 0; }
    friend inline bool operator==(const base_blob& a, uint64_t b) { return a.EqualTo(b); }
    friend inline bool operator!=(const base_blob& a, uint64_t b) { return !a.EqualTo(b); }

    std::string GetHex() const;
    void SetHex(const char* psz);
    void SetHex(const std::string& str);
    std::string ToString() const;
    std::string ToStringReverseEndian() const;

    unsigned char* begin()
    {
        return (unsigned char*)&pn[0];
    }

    unsigned char* end()
    {
        return (unsigned char*)&pn[WIDTH];
    }

    const unsigned char* begin() const
    {
        return (unsigned char*)&pn[0];
    }

    const unsigned char* end() const
    {
        return (unsigned char*)&pn[WIDTH];
    }

    unsigned int size() const
    {
        return sizeof(pn);
    }
//    uint64_t GetUint64(int pos) const
//    {
//        const uint8_t* ptr = data + pos * 8;
//        return ((uint64_t)ptr[0]) | \
//               ((uint64_t)ptr[1]) << 8 | \
//               ((uint64_t)ptr[2]) << 16 | \
//               ((uint64_t)ptr[3]) << 24 | \
//               ((uint64_t)ptr[4]) << 32 | \
//               ((uint64_t)ptr[5]) << 40 | \
//               ((uint64_t)ptr[6]) << 48 | \
//               ((uint64_t)ptr[7]) << 56;
//    }
    uint64_t GetUint64(int pos) const
    {
        return pn[2 * pos] | (uint64_t)pn[2 * pos + 1] << 32;
    }
    uint64_t Get64(int n = 0) const
    {
        return pn[2 * n] | (uint64_t)pn[2 * n + 1] << 32;
    }

    uint32_t Get32(int n = 0) const
    {
        return pn[2 * n];
    }
    /**
     * Returns the position of the highest bit set plus one, or zero if the
     * value is zero.
     */
    unsigned int bits() const;

    uint64_t GetLow64() const
    {
        assert(WIDTH >= 2);
        return pn[0] | (uint64_t)pn[1] << 32;
    }

    unsigned int GetSerializeSize(int nType, int nVersion) const
    {
        return sizeof(pn);
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s.write((char*)pn, sizeof(pn));
    }

    template <typename Stream>
    void Serialize(Stream& s, int nType, int nVersion) const
    {
        s.write((char*)pn, sizeof(pn));
    }
    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s.read((char*)pn, sizeof(pn));
    }
    template <typename Stream>
    void Unserialize(Stream& s, int nType, int nVersion)
    {
        s.read((char*)pn, sizeof(pn));
    }

    friend class uint160;
    friend class uint256;
    friend class uint512;
};

/** 160-bit unsigned big integer. */
class uint160 : public base_blob<160>
{
public:
    uint160() {}
    uint160(const base_blob<160>& b) : base_blob<160>(b) {}
    uint160(uint64_t b) : base_blob<160>(b) {}
    explicit uint160(const std::string& str) : base_blob<160>(str) {}
    explicit uint160(const std::vector<unsigned char>& vch) : base_blob<160>(vch) {}
    explicit uint160(const uint32_t *p, size_t l) : base_blob<160>(p, l) {}

};

/** 256-bit unsigned big integer. */
class uint256 : public base_blob<256>
{
public:
    uint256() {}
    uint256(const base_blob<256>& b) : base_blob<256>(b) {}
    uint256(uint64_t b) : base_blob<256>(b) {}
    explicit uint256(const std::string& str) : base_blob<256>(str) {}
    explicit uint256(const std::vector<unsigned char>& vch) : base_blob<256>(vch) {}
    explicit uint256(const uint32_t *p, size_t l) : base_blob<256>(p, l) {}
    /** A cheap hash function that just returns 64 bits from the result, it can be
     * used when the contents are considered uniformly random. It is not appropriate
     * when the value can easily be influenced from outside as e.g. a network adversary could
     * provide values to trigger worst-case behavior.
     */
    uint64_t GetCheapHash() const
    {
        return ReadLE64((uint8_t) pn);
    }
    /**
     * The "compact" format is a representation of a whole
     * number N using an unsigned 32bit number similar to a
     * floating point format.
     * The most significant 8 bits are the unsigned exponent of base 256.
     * This exponent can be thought of as "number of bytes of N".
     * The lower 23 bits are the mantissa.
     * Bit number 24 (0x800000) represents the sign of N.
     * N = (-1^sign) * mantissa * 256^(exponent-3)
     *
     * Satoshi's original implementation used BN_bn2mpi() and BN_mpi2bn().
     * MPI uses the most significant bit of the first byte as sign.
     * Thus 0x1234560000 is compact (0x05123456)
     * and  0xc0de000000 is compact (0x0600c0de)
     *
     * Bitcoin only uses this "compact" format for encoding difficulty
     * targets, which are unsigned 256bit quantities.  Thus, all the
     * complexities of the sign bit and using base 256 are probably an
     * implementation accident.
     */
    uint256& SetCompact(uint32_t nCompact, bool* pfNegative = NULL, bool* pfOverflow = NULL);
    uint32_t GetCompact(bool fNegative = false) const;
    uint64_t GetHash(const uint256& salt) const;
};

/* uint256 from const char *.
 * This is a separate function because the constructor uint256(const char*) can result
 * in dangerously catching uint256(0).
 */
inline uint256 uint256S(const char* str)
{
    uint256 rv;
    rv.SetHex(str);
    return rv;
}
/* uint256 from std::string.
 * This is a separate function because the constructor uint256(const std::string &str) can result
 * in dangerously catching uint256(0) via std::string(const char*).
 */
inline uint256 uint256S(const std::string& str)
{
    uint256 rv;
    rv.SetHex(str);
    return rv;
}

/** 512-bit unsigned big integer. */
class uint512 : public base_blob<512>
{
public:
    uint512() {}
    uint512(const base_blob<512>& b) : base_blob<512>(b) {}
    uint512(uint64_t b) : base_blob<512>(b) {}
    explicit uint512(const std::string& str) : base_blob<512>(str) {}
    explicit uint512(const std::vector<unsigned char>& vch) : base_blob<512>(vch) {}

    uint256 trim256() const
    {
        uint256 ret;
        for (unsigned int i = 0; i < uint256::WIDTH; i++) {
            ret.pn[i] = pn[i];
        }
        return ret;
    }
};

inline uint512 uint512S(const std::string& str)
{
    uint512 rv;
    rv.SetHex(str);
    return rv;
}

#endif // WISPR_UINT256_H
