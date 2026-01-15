#include "padding.h"
#include <stdexcept>
#include <QByteArray>
#include <QRandomGenerator>
/*
 * PKCS5 / PKCS7 padding
 * padLen is always in range [1..blockSize]
 */
QByteArray Padding::addPKCS5(const QByteArray& data, size_t blockSize)
{
    if (blockSize == 0)
        throw std::invalid_argument("Block size must be > 0");

    size_t padLen = blockSize - (data.size() % blockSize);
    if (padLen == 0)
        padLen = blockSize;

    QByteArray out = data;
    out.append(static_cast<char>(padLen), padLen);
    return out;
}

QByteArray Padding::removePKCS5(const QByteArray& data)
{
    if (data.isEmpty())
        throw std::invalid_argument("PKCS5: data is empty");

    uint8_t padLen = static_cast<uint8_t>(data.back());

    if (padLen == 0 || padLen > data.size())
        throw std::runtime_error("Invalid PKCS5 padding");

    // Verify padding bytes
    for (int i = 0; i < padLen; ++i) {
        if (static_cast<uint8_t>(data[data.size() - 1 - i]) != padLen)
            throw std::runtime_error("Invalid PKCS5 padding");
    }

    return data.left(data.size() - padLen);
}

/*
 * Zero padding
 * Appends 0x00 bytes until multiple of blockSize
 */
QByteArray Padding::addZeroPadding(const QByteArray& data, size_t blockSize)
{
    if (blockSize == 0)
        throw std::invalid_argument("Block size must be > 0");

    size_t padLen = blockSize - (data.size() % blockSize);
    if (padLen == blockSize)
        return data; // already aligned, no padding added

    QByteArray out = data;
    out.append(static_cast<char>(0x00), padLen);
    return out;
}

/*
 * Removes trailing 0x00 bytes
 * Ambiguous by nature - cannot distinguish real zeros
 */
QByteArray Padding::removeZeroPadding(const QByteArray& data)
{
    if (data.isEmpty())
        return data;

    int i = data.size() - 1;
    while (i >= 0 && data[i] == 0x00)
        --i;

    return data.left(i + 1);
}


QByteArray Padding::addISO10126(const QByteArray& data, size_t blockSize)
{
    if (blockSize == 0)
        throw std::invalid_argument("Block size must be > 0");

    size_t padLen = blockSize - (data.size() % blockSize);
    if (padLen == 0)
        padLen = blockSize;

    QByteArray out = data;

    // random bytes except last
    for (size_t i = 0; i < padLen - 1; ++i) {
        char r = static_cast<char>(
            QRandomGenerator::global()->generate() & 0xFF
            );
        out.append(r);
    }

    // last byte = padding length
    out.append(static_cast<char>(padLen));

    return out;
}


QByteArray Padding::removeISO10126(const QByteArray& data)
{
    if (data.isEmpty())
        throw std::invalid_argument("ISO10126: data is empty");

    uint8_t padLen = static_cast<uint8_t>(data.back());

    if (padLen == 0 || padLen > data.size())
        throw std::runtime_error("Invalid ISO10126 padding");

    return data.left(data.size() - padLen);
}
