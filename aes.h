#ifndef AES_H
#define AES_H

#include "IBlockCipher.h"
#include <QByteArray>
#include <cstddef>

class AES : public IBlockCipher {
public:
    explicit AES(int keyBits);

    size_t blockSize() const override;
    size_t keySize() const override;

    void setKey(const QByteArray& key) override;

    QByteArray encryptBlock(const QByteArray& block) override;
    QByteArray decryptBlock(const QByteArray& block) override;

private:
    int m_keyBits;
    int m_rounds;
    QByteArray m_roundKeys; // expanded key
};

#endif // AES_H
