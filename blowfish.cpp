#include "Blowfish.h"
#include <stdexcept>
#include <cstring>
#include <cstdint>


#include "blowfish_tables.h"

Blowfish::Blowfish(int keyBits)
    : m_keyBits(keyBits)
{
    if(keyBits < 32)
    {
        throw std::invalid_argument("Invalid Blowfish key size");
    }
    if (keyBits > 448)
    {
        throw std::invalid_argument("Invalid Blowfish key size");
    }

    if(keyBits % 8 != 0)
    {
        throw std::invalid_argument("Invalid Blowfish key size");
    }
}

size_t Blowfish::blockSize() const { return 8; }
size_t Blowfish::keySize() const { return m_keyBits / 8; }

void Blowfish::setKey(const QByteArray& key)
{
    if (key.size() != keySize())
        throw std::invalid_argument("Invalid Blowfish key length");

    /* -------------------------------------------------
     * 1. Copy initial P-array and S-boxes (π digits)
     * ------------------------------------------------- */
    for (int i = 0; i < ROUNDS + 2; ++i)
        P[i] = static_cast<uint32_t>(parray[i]);

    for (int i = 0; i < 256; ++i) {
        S[0][i] = static_cast<uint32_t>(sbox0[i]);
        S[1][i] = static_cast<uint32_t>(sbox1[i]);
        S[2][i] = static_cast<uint32_t>(sbox2[i]);
        S[3][i] = static_cast<uint32_t>(sbox3[i]);
    }

    /* -------------------------------------------------
     * 2. XOR key material into P-array
     * ------------------------------------------------- */
    int j = 0;
    for (int i = 0; i < ROUNDS + 2; ++i) {
        uint32_t data = 0;
        for (int k = 0; k < 4; ++k) {
            data = (data << 8) | static_cast<uint8_t>(key[j]);
            j = (j + 1) % key.size();
        }
        P[i] ^= data;
    }

    /* -------------------------------------------------
     * 3. Key expansion (encrypt zero block)
     * ------------------------------------------------- */
    uint32_t L = 0, R = 0;

    for (int i = 0; i < ROUNDS + 2; i += 2) {
        encrypt(L, R);
        P[i]     = L;
        P[i + 1] = R;
    }

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 256; j += 2) {
            encrypt(L, R);
            S[i][j]     = L;
            S[i][j + 1] = R;
        }
    }
}

uint32_t Blowfish::F(uint32_t x) const
{
    uint8_t a = (x >> 24) & 0xFF;
    uint8_t b = (x >> 16) & 0xFF;
    uint8_t c = (x >> 8) & 0xFF;
    uint8_t d = x & 0xFF;

    return ((S[0][a] + S[1][b]) ^ S[2][c]) + S[3][d];
}

void Blowfish::encrypt(uint32_t& L, uint32_t& R)
{
    for (int i = 0; i < ROUNDS; ++i) {
        L ^= P[i];
        R ^= F(L);
        std::swap(L, R);
    }
    std::swap(L, R);
    R ^= P[ROUNDS];
    L ^= P[ROUNDS + 1];
}

void Blowfish::decrypt(uint32_t& L, uint32_t& R)
{
    for (int i = ROUNDS + 1; i > 1; --i) {
        L ^= P[i];
        R ^= F(L);
        std::swap(L, R);
    }
    std::swap(L, R);
    R ^= P[1];
    L ^= P[0];
}

QByteArray Blowfish::encryptBlock(const QByteArray& block)
{
    if (block.size() != 8)
        throw std::invalid_argument("Invalid Blowfish block size");

    uint32_t L =
        (static_cast<uint8_t>(block[0]) << 24) |
        (static_cast<uint8_t>(block[1]) << 16) |
        (static_cast<uint8_t>(block[2]) << 8)  |
        (static_cast<uint8_t>(block[3]));

    uint32_t R =
        (static_cast<uint8_t>(block[4]) << 24) |
        (static_cast<uint8_t>(block[5]) << 16) |
        (static_cast<uint8_t>(block[6]) << 8)  |
        (static_cast<uint8_t>(block[7]));

    encrypt(L, R);

    QByteArray out(8, 0);
    out[0] = (L >> 24) & 0xFF;
    out[1] = (L >> 16) & 0xFF;
    out[2] = (L >> 8) & 0xFF;
    out[3] = L & 0xFF;

    out[4] = (R >> 24) & 0xFF;
    out[5] = (R >> 16) & 0xFF;
    out[6] = (R >> 8) & 0xFF;
    out[7] = R & 0xFF;

    return out;
}

QByteArray Blowfish::decryptBlock(const QByteArray& block)
{
    if (block.size() != 8)
        throw std::invalid_argument("Invalid Blowfish block size");

    uint32_t L =
        (static_cast<uint8_t>(block[0]) << 24) |
        (static_cast<uint8_t>(block[1]) << 16) |
        (static_cast<uint8_t>(block[2]) << 8)  |
        (static_cast<uint8_t>(block[3]));

    uint32_t R =
        (static_cast<uint8_t>(block[4]) << 24) |
        (static_cast<uint8_t>(block[5]) << 16) |
        (static_cast<uint8_t>(block[6]) << 8)  |
        (static_cast<uint8_t>(block[7]));

    decrypt(L, R);

    QByteArray out(8, 0);
    out[0] = (L >> 24) & 0xFF;
    out[1] = (L >> 16) & 0xFF;
    out[2] = (L >> 8) & 0xFF;
    out[3] = L & 0xFF;

    out[4] = (R >> 24) & 0xFF;
    out[5] = (R >> 16) & 0xFF;
    out[6] = (R >> 8) & 0xFF;
    out[7] = R & 0xFF;

    return out;
}
