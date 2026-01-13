#ifndef IDEA_H
#define IDEA_H
#include "IBlockCipher.h"
#include <stddef.h>
#include<QByteArray>
class IDEA : public IBlockCipher
{
public:
    explicit IDEA();

    size_t blockSize() const override;
    size_t keySize() const override;

    void setKey(const QByteArray& key) override;

    QByteArray encryptBlock(const QByteArray& block) override;
    QByteArray decryptBlock(const QByteArray& block) override;

private:
    int m_keyBits;
    QByteArray m_key;
};

#endif // IDEA_H
