#ifndef BLOWFISH_H
#define BLOWFISH_H
#include "IBlockCipher.h"
#include <stddef.h>
#include<QByteArray>
class Blowfish : public IBlockCipher
{
public:
    explicit Blowfish(int keyBits);

    size_t blockSize() const override;
    size_t keySize() const override;

    void setKey(const QByteArray& key) override;

    QByteArray encryptBlock(const QByteArray& block) override;
    QByteArray decryptBlock(const QByteArray& block) override;

private:
    QByteArray m_key;
    static const int ROUNDS = 16;

    uint32_t P[ROUNDS + 2];
    uint32_t S[4][256];

    int m_keyBits;

    void encrypt(uint32_t& L, uint32_t& R);
    void decrypt(uint32_t& L, uint32_t& R);
    uint32_t F(uint32_t x) const;
};

#endif // BLOWFISH_H
