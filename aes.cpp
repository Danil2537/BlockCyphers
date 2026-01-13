#include "aes.h"
#include <stdexcept>
#include "aes.h"
AES::AES(int keyBits)
    : m_keyBits(keyBits)
{
    if (keyBits != 128 && keyBits != 192 && keyBits != 256)
        throw std::invalid_argument("Invalid AES key size");
}

size_t AES::blockSize() const {
    return 16; // AES block size = 128 bits
}

size_t AES::keySize() const {
    return m_keyBits / 8;
}

void AES::setKey(const QByteArray& key) {
    if (key.size() != keySize())
        throw std::invalid_argument("Invalid AES key length");

    // In real AES:
    //  key expansion happens here
    m_roundKey = key;
}

QByteArray AES::encryptBlock(const QByteArray& block) {
    if (block.size() != blockSize())
        throw std::invalid_argument("Invalid AES block size");

    QByteArray out = block;

    // NOT real AES, placeholder transformation
    for (int i = 0; i < out.size(); ++i)
        out[i] ^= m_roundKey[i % m_roundKey.size()];

    return out;
}

QByteArray AES::decryptBlock(const QByteArray& block) {
    // XOR-based placeholder is symmetric
    return encryptBlock(block);
}
