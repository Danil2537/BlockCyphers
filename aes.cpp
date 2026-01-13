#include "aes.h"
#include <stdexcept>
#include "aes.h"

#include "aes_sbox.inc"
#include "aes_inv_sbox.inc"

#include <cstring>
#include <algorithm>

static const uint8_t RCON[11] = {
    0x00,
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36
};

// static const uint8_t RCON[256] =
//     {
//         0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
//         0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
//         0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
//         0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
//         0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
//         0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
//         0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
//         0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
//         0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
//         0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
//         0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
//         0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
//         0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
//         0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
//         0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
//         0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
// };

static uint8_t gfMul(uint8_t a, uint8_t b)
{
    uint8_t res = 0;
    while (b) {
        if (b & 1) res ^= a;
        a = (a << 1) ^ (a & 0x80 ? 0x1B : 0);
        b >>= 1;
    }
    return res;
}


AES::AES(int keyBits)
    : m_keyBits(keyBits)
{
    if (keyBits == 128) m_rounds = 10;
    else if (keyBits == 192) m_rounds = 12;
    else if (keyBits == 256) m_rounds = 14;
    else
        throw std::invalid_argument("Invalid AES key size");
}


size_t AES::blockSize() const { return 16; }
size_t AES::keySize() const { return m_keyBits / 8; }

void AES::setKey(const QByteArray& key)
{
    if (key.size() != keySize())
        throw std::invalid_argument("Invalid AES key length");

    const int Nb = 4;                     // block size in words
    const int Nk = keySize() / 4;         // key size in words
    const int Nr = m_rounds;              // number of rounds

    // Total number of 32-bit words in expanded key
    const int totalWords = Nb * (Nr + 1);

    m_roundKeys.resize(totalWords * 4);
    uint8_t* w = reinterpret_cast<uint8_t*>(m_roundKeys.data());

    // 1. Copy original key
    memcpy(w, key.constData(), key.size());

    // 2. Expand key
    for (int i = Nk; i < totalWords; ++i) {
        uint8_t temp[4];

        // temp = w[i - 1]
        for (int j = 0; j < 4; ++j)
            temp[j] = w[4 * (i - 1) + j];

        // Apply schedule core every Nk words
        if (i % Nk == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // SubWord
            for (int j = 0; j < 4; ++j)
                temp[j] = SBOX[temp[j]];

            // Rcon
            temp[0] ^= RCON[i / Nk];
        }
        // AES-256 extra SubWord
        else if (Nk == 8 && (i % Nk) == 4) {
            for (int j = 0; j < 4; ++j)
                temp[j] = SBOX[temp[j]];
        }

        // w[i] = w[i - Nk] ^ temp
        for (int j = 0; j < 4; ++j)
            w[4 * i + j] = w[4 * (i - Nk) + j] ^ temp[j];
    }
}

static void addRoundKey(uint8_t s[4][4], const uint8_t* rk)
{
    for (int c = 0; c < 4; ++c)
        for (int r = 0; r < 4; ++r)
            s[r][c] ^= rk[4*c + r];
}


static void subBytes(uint8_t s[4][4])
{
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            s[r][c] = SBOX[s[r][c]];
}

static void invSubBytes(uint8_t s[4][4])
{
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            s[r][c] = INV_SBOX[s[r][c]];
}
static void shiftRows(uint8_t s[4][4])
{
    uint8_t t;

    t=s[1][0]; s[1][0]=s[1][1]; s[1][1]=s[1][2]; s[1][2]=s[1][3]; s[1][3]=t;
    std::swap(s[2][0],s[2][2]); std::swap(s[2][1],s[2][3]);
    t=s[3][3]; s[3][3]=s[3][2]; s[3][2]=s[3][1]; s[3][1]=s[3][0]; s[3][0]=t;
}

static void invShiftRows(uint8_t s[4][4])
{
    uint8_t t;

    t=s[1][3]; s[1][3]=s[1][2]; s[1][2]=s[1][1]; s[1][1]=s[1][0]; s[1][0]=t;
    std::swap(s[2][0],s[2][2]); std::swap(s[2][1],s[2][3]);
    t=s[3][0]; s[3][0]=s[3][1]; s[3][1]=s[3][2]; s[3][2]=s[3][3]; s[3][3]=t;
}

static void mixColumns(uint8_t s[4][4])
{
    for (int c = 0; c < 4; ++c) {
        uint8_t a=s[0][c], b=s[1][c], c1=s[2][c], d=s[3][c];
        s[0][c] = gfMul(a,2)^gfMul(b,3)^c1^d;
        s[1][c] = a^gfMul(b,2)^gfMul(c1,3)^d;
        s[2][c] = a^b^gfMul(c1,2)^gfMul(d,3);
        s[3][c] = gfMul(a,3)^b^c1^gfMul(d,2);
    }
}

static void invMixColumns(uint8_t s[4][4])
{
    for (int c = 0; c < 4; ++c) {
        uint8_t a = s[0][c], b = s[1][c], c1 = s[2][c], d = s[3][c];
        s[0][c] = gfMul(a,14) ^ gfMul(b,11) ^ gfMul(c1,13) ^ gfMul(d,9);
        s[1][c] = gfMul(a,9)  ^ gfMul(b,14) ^ gfMul(c1,11) ^ gfMul(d,13);
        s[2][c] = gfMul(a,13) ^ gfMul(b,9)  ^ gfMul(c1,14) ^ gfMul(d,11);
        s[3][c] = gfMul(a,11) ^ gfMul(b,13) ^ gfMul(c1,9)  ^ gfMul(d,14);
    }
}


QByteArray AES::encryptBlock(const QByteArray& block)
{
    if (block.size() != 16)
        throw std::invalid_argument("Invalid AES block size");

    uint8_t s[4][4];
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            s[r][c] = static_cast<uint8_t>(block[c*4 + r]);

    const uint8_t* rk = reinterpret_cast<const uint8_t*>(m_roundKeys.data());

    addRoundKey(s, rk);

    for (int r = 1; r < m_rounds; ++r) {
        subBytes(s);
        shiftRows(s);
        mixColumns(s);
        addRoundKey(s, rk + 16*r);
    }

    subBytes(s);
    shiftRows(s);
    addRoundKey(s, rk + 16*m_rounds);

    QByteArray out;
    out.resize(16);
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            out[c*4 + r] = static_cast<uint8_t>(s[r][c]);
    return out;

    //return QByteArray(reinterpret_cast<char*>(s), 16);
}


QByteArray AES::decryptBlock(const QByteArray& block)
{
    if (block.size() != 16)
        throw std::invalid_argument("Invalid AES block size");

    uint8_t s[4][4];
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            s[r][c] = static_cast<uint8_t>(block[c*4 + r]);

    const uint8_t* rk = reinterpret_cast<const uint8_t*>(m_roundKeys.data());

    addRoundKey(s, rk + 16*m_rounds);

    for (int r = m_rounds-1; r > 0; --r) {
        invShiftRows(s);
        invSubBytes(s);
        addRoundKey(s, rk + 16*r);
        invMixColumns(s);
    }

    invShiftRows(s);
    invSubBytes(s);
    addRoundKey(s, rk);

    QByteArray out;
    out.resize(16);
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            out[c*4 + r] = static_cast<uint8_t>(s[r][c]);
    return out;
    //return QByteArray(reinterpret_cast<char*>(s), 16);
}

