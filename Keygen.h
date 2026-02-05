#ifndef KEYGEN_H
#define KEYGEN_H

#include <QByteArray>
#include <QRandomGenerator>
#include <stdexcept>

class KeyGenerator {
public:
    static QByteArray generateKey(int bits)
    {
        if (bits <= 0 || bits % 8 != 0)
            throw std::invalid_argument("Key size must be divisible by 8");

        int bytes = bits / 8;
        QByteArray key;
        key.reserve(bytes);

        // Use printable ASCII chars (33..126)
        for (int i = 0; i < bytes; ++i) {
            char c = static_cast<char>(QRandomGenerator::global()->bounded(33, 127));
            key.append(c);
        }

        return key;
    }
};

#endif // KEYGEN_H
