#ifndef CIPHERCONTEXT_H
#define CIPHERCONTEXT_H
#include<QByteArray>
#include <stdio.h>
#include <memory>
#include "IBlockCipher.h"
#include "IMode.h"

class CipherContext {
public:
    CipherContext(
        std::unique_ptr<IBlockCipher> cipher,
        std::unique_ptr<IMode> mode
        );

    void setKey(const QByteArray& key);
    void setIV(const QByteArray& iv);
    void setPadding(PaddingType p) {
        m_padding = p;
    }

    QByteArray encrypt(const QByteArray& data);
    QByteArray decrypt(const QByteArray& data);

private:
    std::unique_ptr<IBlockCipher> m_cipher;
    std::unique_ptr<IMode> m_mode;
    PaddingType m_padding = PaddingType::none;
};

#endif // CIPHERCONTEXT_H
