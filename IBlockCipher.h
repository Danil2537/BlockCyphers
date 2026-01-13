#ifndef IBLOCKCIPHER_H
#define IBLOCKCIPHER_H
#include<QByteArray>
#include <stdio.h>
class IBlockCipher {
public:
    virtual ~IBlockCipher() = default;

    virtual size_t blockSize() const = 0;
    virtual size_t keySize() const = 0;

    virtual void setKey(const QByteArray& key) = 0;

    virtual QByteArray encryptBlock(const QByteArray& block) = 0;
    virtual QByteArray decryptBlock(const QByteArray& block) = 0;
};

#endif // IBLOCKCIPHER_H
