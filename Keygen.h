#ifndef KEYGEN_H
#define KEYGEN_H
#include <iostream>
class KeyGenerator {
public:
    static QByteArray generateKey(int bits)
    {
        std::cout<<"Keygen generateKey\n";
    }
};

class IVGenerator {
public:
    static QByteArray generateIV(size_t blockSize);
};

#endif // KEYGEN_H
