#ifndef CBC_H
#define CBC_H

#include "imode.h"

class CBC: public IMode {
    QByteArray iv;

public:

    explicit CBC(){}

    void setIV(const QByteArray& iv_) override {
        iv = iv_;
    }

    // QByteArray process(
    //     IBlockCipher& cipher,
    //     const QByteArray& data,
    //     Operation op
    //     ) override;



    static QByteArray xorBlocks(const QByteArray& a, const QByteArray& b) {
        QByteArray out = a;
        for (int i = 0; i < a.size(); ++i)
            out[i] ^= b[i];
        return out;
    }

    QByteArray process(
        IBlockCipher& cipher,
        const QByteArray& data,
        Operation op
        ) {
        const int blockSize = cipher.blockSize();

        if (!iv.isEmpty() && iv.size() != blockSize)
            throw std::runtime_error("Invalid IV size");

        if (data.size() % blockSize != 0)
            throw std::runtime_error("CBC requires padded input");

        QByteArray result;
        QByteArray prev;
        if (iv.isEmpty()) {
            prev = QByteArray(blockSize, 0); // zero IV
        } else {
            prev = iv;
        }

        for (int offset = 0; offset < data.size(); offset += blockSize) {
            QByteArray block = data.mid(offset, blockSize);

            if (op == Operation::Encrypt) {
                QByteArray xored = xorBlocks(block, prev);
                QByteArray encrypted = cipher.encryptBlock(xored);
                result.append(encrypted);
                prev = encrypted;
            }
            else {
                QByteArray decrypted = cipher.decryptBlock(block);
                QByteArray plain = xorBlocks(decrypted, prev);
                result.append(plain);
                prev = block;
            }
        }

        return result;
    }
};

#endif
