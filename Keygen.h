#ifndef KEYGEN_H
#define KEYGEN_H
#include <iostream>
#include <QRandomGenerator>
#include <stdexcept>
class KeyGenerator {
public:
    static QByteArray generateKey(int bits)
    {
        if (bits <= 0 || bits % 8 != 0)
            throw std::invalid_argument("Key size must be divisible by 8");

        int bytes = bits / 8;
        QByteArray key(bytes, Qt::Uninitialized);

        QRandomGenerator::system()->generate(
            reinterpret_cast<quint32*>(key.data()),
            reinterpret_cast<quint32*>(key.data() + key.size())
            );

        return key;
    }
};

class IVGenerator {
public:
    static QByteArray generateIV(size_t blockSize)
    {
        if (blockSize == 0)
            throw std::invalid_argument("Block size must be > 0");

        QByteArray iv(static_cast<int>(blockSize), Qt::Uninitialized);

        QRandomGenerator::system()->generate(
            reinterpret_cast<quint32*>(iv.data()),
            reinterpret_cast<quint32*>(iv.data() + iv.size())
            );

        return iv;
    }
};

#endif // KEYGEN_H
