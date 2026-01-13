#ifndef DES_H
#define DES_H
#include "IBlockCipher.h"
#include <stddef.h>
#include<QByteArray>
class DES : public IBlockCipher
{
public:
    explicit DES();


    size_t blockSize() const override;
    size_t keySize() const override;

    void setKey(const QByteArray& key) override;

    QByteArray encryptBlock(const QByteArray& block) override;
    QByteArray decryptBlock(const QByteArray& block) override;

private:
    int m_keyBits;
    QByteArray m_key;
};

#endif // DES_H
