#include "xtea.h"
#include <stdexcept>

XTEA::XTEA()
{
    m_key.fill(0);
}

size_t XTEA::blockSize() const
{
    return 8; // 64-bit block
}

size_t XTEA::keySize() const
{
    return 16; // 128-bit key
}

void XTEA::setKey(const QByteArray& key)
{
    if (key.size() != static_cast<int>(keySize()))
        throw std::invalid_argument("Invalid XTEA key length");

    for (int i = 0; i < 4; ++i) {
        m_key[i] =
            (static_cast<uint8_t>(key[i * 4 + 0]) << 24) |
            (static_cast<uint8_t>(key[i * 4 + 1]) << 16) |
            (static_cast<uint8_t>(key[i * 4 + 2]) << 8)  |
            (static_cast<uint8_t>(key[i * 4 + 3]));
    }
}

QByteArray XTEA::encryptBlock(const QByteArray& block)
{
    if (block.size() != 8)
        throw std::invalid_argument("Invalid XTEA block size");

    uint32_t v0 =
        (static_cast<uint8_t>(block[0]) << 24) |
        (static_cast<uint8_t>(block[1]) << 16) |
        (static_cast<uint8_t>(block[2]) << 8)  |
        (static_cast<uint8_t>(block[3]));

    uint32_t v1 =
        (static_cast<uint8_t>(block[4]) << 24) |
        (static_cast<uint8_t>(block[5]) << 16) |
        (static_cast<uint8_t>(block[6]) << 8)  |
        (static_cast<uint8_t>(block[7]));

    uint32_t sum = 0;

    for (int i = 0; i < ROUNDS; ++i) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + m_key[sum & 3]);
        sum += DELTA;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + m_key[(sum >> 11) & 3]);
    }

    QByteArray out(8, 0);
    out[0] = (v0 >> 24) & 0xFF;
    out[1] = (v0 >> 16) & 0xFF;
    out[2] = (v0 >> 8) & 0xFF;
    out[3] = v0 & 0xFF;

    out[4] = (v1 >> 24) & 0xFF;
    out[5] = (v1 >> 16) & 0xFF;
    out[6] = (v1 >> 8) & 0xFF;
    out[7] = v1 & 0xFF;

    return out;
}

QByteArray XTEA::decryptBlock(const QByteArray& block)
{
    if (block.size() != 8)
        throw std::invalid_argument("Invalid XTEA block size");

    uint32_t v0 =
        (static_cast<uint8_t>(block[0]) << 24) |
        (static_cast<uint8_t>(block[1]) << 16) |
        (static_cast<uint8_t>(block[2]) << 8)  |
        (static_cast<uint8_t>(block[3]));

    uint32_t v1 =
        (static_cast<uint8_t>(block[4]) << 24) |
        (static_cast<uint8_t>(block[5]) << 16) |
        (static_cast<uint8_t>(block[6]) << 8)  |
        (static_cast<uint8_t>(block[7]));

    uint32_t sum = DELTA * ROUNDS;

    for (int i = 0; i < ROUNDS; ++i) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + m_key[(sum >> 11) & 3]);
        sum -= DELTA;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + m_key[sum & 3]);
    }

    QByteArray out(8, 0);
    out[0] = (v0 >> 24) & 0xFF;
    out[1] = (v0 >> 16) & 0xFF;
    out[2] = (v0 >> 8) & 0xFF;
    out[3] = v0 & 0xFF;

    out[4] = (v1 >> 24) & 0xFF;
    out[5] = (v1 >> 16) & 0xFF;
    out[6] = (v1 >> 8) & 0xFF;
    out[7] = v1 & 0xFF;

    return out;
}
