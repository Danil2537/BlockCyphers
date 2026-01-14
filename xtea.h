#ifndef XTEA_H
#define XTEA_H

#include "IBlockCipher.h"
#include <array>
#include <cstdint>

class XTEA : public IBlockCipher
{
public:
    XTEA();

    size_t blockSize() const override;
    size_t keySize() const override;

    void setKey(const QByteArray& key) override;

    QByteArray encryptBlock(const QByteArray& block) override;
    QByteArray decryptBlock(const QByteArray& block) override;

private:
    static constexpr uint32_t DELTA = 0x9E3779B9;
    static constexpr int ROUNDS = 32;

    std::array<uint32_t, 4> m_key;
};

#endif // XTEA_H
