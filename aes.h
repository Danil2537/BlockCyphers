#ifndef AES_H
#define AES_H
#include"IBlockCipher.h"
#include<QByteArray>
#include <stddef.h>
class AES: public IBlockCipher {
public:
    explicit AES(int keyBits);/*
        : m_keyBits(keyBits)
    {
        if (keyBits != 128 && keyBits != 192 && keyBits != 256)
            throw std::invalid_argument("Invalid AES key size");
    }// 128 / 192 / 256*/

    size_t blockSize() const override; // 16 bytes
    size_t keySize() const override;

    void setKey(const QByteArray& key) override;

    QByteArray encryptBlock(const QByteArray& block) override;
    QByteArray decryptBlock(const QByteArray& block) override;
private:
    int m_keyBits;
    QByteArray m_roundKey; // simplified
};

#endif // AES_H
