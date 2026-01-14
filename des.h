#ifndef DES_H
#define DES_H

#include "IBlockCipher.h"
#include <array>

class DES : public IBlockCipher {
public:
    explicit DES();

    size_t blockSize() const override;
    size_t keySize() const override;

    void setKey(const QByteArray& key) override;

    QByteArray encryptBlock(const QByteArray& block) override;
    QByteArray decryptBlock(const QByteArray& block) override;

private:
    uint64_t subkeys[16];

    uint64_t permute(uint64_t in, const int* table, int n, int inBits);
    uint32_t feistel(uint32_t r, uint64_t k);

    void generateSubkeys(uint64_t key);
};

#endif // DES_H
