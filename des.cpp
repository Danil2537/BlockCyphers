#include"DES.h"
#include<stddef.h>
#include<QByteArray>
#include "DES.h"
#include <stdexcept>
#include <cstdint>

/* ---- DES tables (standard) ---- */
static const int IP[64] = {
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
};

static const int FP[64] = {
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25
};

static const int E[48] = {
    32,1,2,3,4,5, 4,5,6,7,8,9,
    8,9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32,1
};

static const int P[32] = {
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
};

static const int SBOX1[64] = {
    14,	4, 13,	1,	2,	15,	11,	8,	3,	10,	6, 12,	5,	9,	0,	7,
    0,	15,	7,	4,	14,	2,	13,	1,	10,	6,	12,	11,	9,	5,	3,	8,
    4,	1,	14,	8,	13,	6,	2,	11,	15,	12,	9,	7,	3,	10,	5,	0,
    15,	12,	8,	2,	4,	9,	1,	7,	5,	11,	3,	14,	10,	0, 6,	13
};
static const int SBOX2[64] = {
   15,	1,	8,	14,	6,	11,	3,	4,	9,	7,	2,	13,	12,	0,	5,	10,
    3,	13,	4,	7,	15,	2,	8,	14,	12,	0,	1,	10,	6,	9,	11,	5,
   0,	14,	7,	11,	10,	4,	13,	1,	5,	8,	12,	6,	9,	3,	2,	15,
   13,	8,	10,	1,	3,	15,	4,	2,	11,	6,	7,	12,	0,	5,	14,	9
};
static const int SBOX3[64] = {
    10,	0,	9,	14,	6,	3,	15,	5,	1,	13,	12,	7,	11,	4,	2,	8,
    13,	7,	0,	9,	3,	4,	6,	10,	2,	8,	5,	14,	12,	11,	15,	1,
    13,	6,	4,	9,	8,	15,	3,	0,	11,	1,	2,	12,	5,	10,	14,	7,
    1,	10, 13,	0,	6,	9,	8,	7,	4,	15,	14,	3,	11,	5,	2,	12
};

static const int SBOX4[64] = {
    7,	13,	14,	3,	0,	6,	9,	10,	1,	2,	8,	5,	11,	12,	4,	15,
    13,	8,	11,	5,	6,	15,	0,	3,	4,	7,	2,	12,	1,	10,	14,	9,
    10,	6,	9,	0,	12,	11,	7,	13,	15,	1,	3,	14,	5,	2,	8,	4,
    3,	15,	0,	6,	10,	1,	13,	8,	9,	4,	5,	11,	12,	7,	2,	14
};

static const int SBOX5[64] = {
    2,	12,	4,	1,	7,	10,	11,	6,	8,	5,	3,	15,	13,	0,	14,	9,
    14,	11,	2,	12,	4, 7,	13,	1,	5,	0,	15,	10,	3,	9,	8,	6,
    4,	2,	1,	11,	10,	13,	7,	8,	15,	9,	12,	5,	6,	3,	0,	14,
    11,	8,	12,	7,	1,	14,	2,	13,	6,	15,	0,	9,	10,	4,	5,	3
};

static const int SBOX6[64] = {
    12,	1,	10,	15,	9,	2,	6,	8,	0,	13,	3,	4,	14,	7,	5,	11,
    10,	15,	4,	2,	7,	12,	9,	5,	6,	1,	13,	14,	0,	11,	3,	8,
    9,	14,	15,	5,	2,	8,	12,	3,	7,	0,	4,	10,	1,	13,	11,	6,
    4, 3,	2,	12,	9,	5,	15,	10,	11,	14,	1,	7,	6,	0,	8,	13
};

static const int SBOX7[64] = {
    4,	11,	2,	14,	15,	0,	8,	13,	3,	12,	9,	7,	5,	10,	6,	1,
    13,	0,	11,	7,	4,	9,	1,	10,	14,	3,	5,	12,	2,	15,	8,	6,
    1,	4,	11,	13,	12,	3,	7,	14,	10,	15,	6,	8,	0,	5,	9,	2,
    6,	11,	13,	8,	1,	4,	10,	7,	9,	5,	0,	15,	14,	2,	3,	12
};

static const int SBOX8[64] = {
    13,	2,	8,	4,	6,	15,	11,	1,	10,	9,	3,	14,	5,	0,	12,	7,
    1,	15,	13,	8,	10,	3,	7,	4,	12,	5,	6,	11,	0,	14,	9,	2,
    7,	11,	4,	1,	9,	12,	14,	2,	0,	6,	10,	13,	15,	3,	5,	8,
    2,	1,	14,	7,	4,	10,	8,	13,	15,	12,	9,	0,	3,	5,	6,	11
};

static const int SHIFTS[16] = {
    1,1,2,2,2,2,2,2,
    1,2,2,2,2,2,2,1
};

static const int PC1[56] = {
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
};

// Permuted Choice 2 (PC-2) – selects 48 bits from 56-bit key
static const int PC2[48] = {
    14,17,11,24,1,5,3,28,
    15,6,21,10,23,19,12,4,
    26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,
    51,45,33,48,44,49,39,56,
    34,53,46,42,50,36,29,32
};

DES::DES() {}


uint64_t DES::permute(uint64_t in, const int* table, int n, int inBits)
{
    uint64_t out = 0;
    for (int i = 0; i < n; ++i) {
        out <<= 1;
        out |= (in >> (inBits - table[i])) & 1;
    }
    return out;
}

// DES Feistel function
uint32_t DES::feistel(uint32_t r, uint64_t k)
{
    // 1. Expand 32-bit R to 48 bits using E table
    uint64_t e = 0;
    for (int i = 0; i < 48; ++i) {
        e <<= 1;
        e |= (r >> (32 - E[i])) & 1;
    }

    // 2. XOR with subkey
    e ^= k;

    // 3. S-box substitution
    uint32_t out = 0;
    for (int i = 0; i < 8; ++i) {
        int sixBits = (e >> (42 - 6*i)) & 0x3F; // extract 6 bits

        int row = ((sixBits & 0x20) >> 4) | (sixBits & 0x01); // bits 1 & 6
        int col = (sixBits >> 1) & 0x0F;                     // bits 2–5

        int sVal;
        switch(i) {
        case 0: sVal = SBOX1[row*16 + col]; break;
        case 1: sVal = SBOX2[row*16 + col]; break;
        case 2: sVal = SBOX3[row*16 + col]; break;
        case 3: sVal = SBOX4[row*16 + col]; break;
        case 4: sVal = SBOX5[row*16 + col]; break;
        case 5: sVal = SBOX6[row*16 + col]; break;
        case 6: sVal = SBOX7[row*16 + col]; break;
        case 7: sVal = SBOX8[row*16 + col]; break;
        }

        out = (out << 4) | (sVal & 0x0F); // 4-bit output
    }

    // 4. Apply permutation P
    out = static_cast<uint32_t>(permute(out, P, 32,32));
    return out;
}

size_t DES::blockSize() const { return 8; }
size_t DES::keySize() const { return 8; }

void DES::generateSubkeys(uint64_t key)
{
    uint64_t permutedKey = permute(key, PC1, 56,64);

    // Split into two 28-bit halves
    uint32_t C = (permutedKey >> 28) & 0x0FFFFFFF;
    uint32_t D = permutedKey & 0x0FFFFFFF;

    for (int i = 0; i < 16; ++i) {
        // Left rotate each half
        C = ((C << SHIFTS[i]) | (C >> (28 - SHIFTS[i]))) & 0x0FFFFFFF;
        D = ((D << SHIFTS[i]) | (D >> (28 - SHIFTS[i]))) & 0x0FFFFFFF;

        // Combine halves and apply PC2 → 48-bit subkey
        uint64_t combined = (static_cast<uint64_t>(C) << 28) | D;
        subkeys[i] = permute(combined, PC2, 48, 56);
    }
}

void DES::setKey(const QByteArray& key)
{
    if (key.size() != 7)
        throw std::invalid_argument("Invalid DES key size");

    uint64_t k = 0;
    for (int i = 0; i < 7; ++i)
        k = (k << 8) | static_cast<uint8_t>(key[i]);

    generateSubkeys(k);
}

QByteArray DES::encryptBlock(const QByteArray& block)
{
    if (block.size() != 8)
        throw std::invalid_argument("Invalid DES block size");

    uint64_t data = 0;
    for (int i = 0; i < 8; ++i)
        data = (data << 8) | static_cast<uint8_t>(block[i]);

    data = permute(data, IP, 64,64);

    uint32_t L = data >> 32;
    uint32_t R = data & 0xFFFFFFFF;

    for (int i = 0; i < 16; ++i) {
        uint32_t tmp = R;
        R = L ^ feistel(R, subkeys[i]);
        L = tmp;
    }

    data = (uint64_t(R) << 32) | L;
    data = permute(data, FP, 64,64);

    QByteArray out(8, 0);
    for (int i = 7; i >= 0; --i) {
        out[i] = data & 0xFF;
        data >>= 8;
    }
    return out;
}

QByteArray DES::decryptBlock(const QByteArray& block)
{
    if (block.size() != 8)
        throw std::invalid_argument("Invalid DES block size");

    uint64_t data = 0;
    for (int i = 0; i < 8; ++i)
        data = (data << 8) | static_cast<uint8_t>(block[i]);

    data = permute(data, IP, 64,64);

    uint32_t L = data >> 32;
    uint32_t R = data & 0xFFFFFFFF;

    for (int i = 15; i >= 0; --i) {
        uint32_t tmp = R;
        R = L ^ feistel(R, subkeys[i]);
        L = tmp;
    }

    data = (uint64_t(R) << 32) | L;
    data = permute(data, FP, 64, 64);

    QByteArray out(8, 0);
    for (int i = 7; i >= 0; --i) {
        out[i] = data & 0xFF;
        data >>= 8;
    }
    return out;
}

