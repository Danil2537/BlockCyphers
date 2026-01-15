//     CipherContext(
//     std::unique_ptr<IBlockCipher> cipher,
//     std::unique_ptr<IMode> mode
//     );

// void setKey(const QByteArray& key);
// void setIV(const QByteArray& iv);

// QByteArray encrypt(const QByteArray& data);
// QByteArray decrypt(const QByteArray& data);

// private:
// std::unique_ptr<IBlockCipher> m_cipher;
// std::unique_ptr<IMode> m_mode;
// };

#include "CipherContext.h"
#include <iostream>
#include "CipherContext.h"
#include <stdexcept>
#include"enums.h"
#include"Padding.h"

CipherContext::CipherContext(
    std::unique_ptr<IBlockCipher> cipher,
    std::unique_ptr<IMode> mode
    )
    : m_cipher(std::move(cipher)),
    m_mode(std::move(mode))
{
    if (!m_cipher || !m_mode)
        throw std::invalid_argument("CipherContext: null cipher or mode");
}

void CipherContext::setKey(const QByteArray& key)
{
    if (!m_cipher)
        throw std::runtime_error("Cipher not initialized");

    m_cipher->setKey(key);
}

void CipherContext::setIV(const QByteArray& iv)
{
    if (!m_mode)
        throw std::runtime_error("Mode not initialized");

    m_mode->setIV(iv);
}

QByteArray CipherContext::encrypt(const QByteArray& data)
{
    if (!m_cipher || !m_mode)
        throw std::runtime_error("CipherContext not properly initialized");

    QByteArray input = data;
    if (m_padding == PaddingType::PKCS5)
        input = Padding::addPKCS5(input, m_cipher->blockSize());
    else if (m_padding == PaddingType::zero)
        input = Padding::addZeroPadding(input, m_cipher->blockSize());
    else if (m_padding == PaddingType::ISO10126)
        input = Padding::addISO10126(input, m_cipher->blockSize());

    return m_mode->process(
        *m_cipher,
        input,
        Operation::Encrypt
        );
}

QByteArray CipherContext::decrypt(const QByteArray& data)
{
    if (!m_cipher || !m_mode)
        throw std::runtime_error("CipherContext not properly initialized");


    QByteArray output =
        m_mode->process(*m_cipher, data, Operation::Decrypt);

    if (m_padding == PaddingType::PKCS5)
        output = Padding::removePKCS5(output);
    else if (m_padding == PaddingType::zero)
        output = Padding::removeZeroPadding(output);
    else if (m_padding == PaddingType::ISO10126)
        output = Padding::removeISO10126(output);


    return output;
}

