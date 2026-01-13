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

    return m_mode->process(
        *m_cipher,
        data,
        Operation::Encrypt
        );
}

QByteArray CipherContext::decrypt(const QByteArray& data)
{
    if (!m_cipher || !m_mode)
        throw std::runtime_error("CipherContext not properly initialized");

    return m_mode->process(
        *m_cipher,
        data,
        Operation::Decrypt
        );
}

