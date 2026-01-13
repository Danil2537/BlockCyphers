#ifndef ECB_H
#define ECB_H

#include "imode.h"

class ECB : public IMode {
public:
    explicit ECB() {}

    // ECB does not use IV
    void setIV(const QByteArray&) override {}

    QByteArray process(
        IBlockCipher& cipher,
        const QByteArray& data,
        Operation op
        ) override
    {
        const int blockSize = cipher.blockSize();

        if (data.size() % blockSize != 0)
            throw std::runtime_error("ECB requires padded input");

        QByteArray result;
        result.reserve(data.size());

        for (int offset = 0; offset < data.size(); offset += blockSize) {
            QByteArray block = data.mid(offset, blockSize);

            QByteArray out =
                (op == Operation::Encrypt)
                    ? cipher.encryptBlock(block)
                    : cipher.decryptBlock(block);

            result.append(out);
        }

        return result;
    }
};

#endif // ECB_H
