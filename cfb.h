#ifndef CFB_H
#define CFB_H

#include "imode.h"
#include <algorithm>
class CFB : public IMode {
    QByteArray iv;

public:
    explicit CFB() {}

    void setIV(const QByteArray& iv_) override {
        iv = iv_;
    }

    QByteArray process(
        IBlockCipher& cipher,
        const QByteArray& data,
        Operation op
        ) override
    {
        const int blockSize = cipher.blockSize();

        if (iv.size()>0 && iv.size() != blockSize)
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

            // Encrypt feedback register
            QByteArray keystream = cipher.encryptBlock(feedback);

            // XOR plaintext/ciphertext with keystream
            QByteArray out = chunk;
            for (int i = 0; i < chunkSize; ++i)
                out[i] ^= keystream[i];

            result.append(out);

            // Update feedback register
            if (op == Operation::Encrypt)
                feedback = out;
            else
                feedback = chunk;
        }

        return result;
    }
};

#endif // CFB_H
