#ifndef OFB_H
#define OFB_H

#include "imode.h"

class OFB : public IMode {
    QByteArray iv;

public:
    explicit OFB() {}

    void setIV(const QByteArray& iv_) override {
        iv = iv_;
    }

    QByteArray process(
        IBlockCipher& cipher,
        const QByteArray& data,
        Operation /*op*/
        ) override
    {
        const int blockSize = cipher.blockSize();

        if (!iv.isEmpty() && iv.size() != blockSize)
            throw std::runtime_error("Invalid IV size");

        QByteArray result;
        result.reserve(data.size());

        QByteArray feedback;
        if (iv.isEmpty())
            feedback = QByteArray(blockSize, 0);
        else
            feedback = iv;

        for (int offset = 0; offset < data.size(); offset += blockSize) {
            const qsizetype remaining = data.size() - offset;
            const int chunkSize = remaining < blockSize
                                      ? static_cast<int>(remaining)
                                      : blockSize;
            QByteArray chunk = data.mid(offset, chunkSize);

            // Generate keystream
            feedback = cipher.encryptBlock(feedback);

            // XOR with plaintext / ciphertext
            QByteArray out = chunk;
            for (int i = 0; i < chunkSize; ++i)
                out[i] ^= feedback[i];

            result.append(out);
        }

        return result;
    }
};

#endif // OFB_H
