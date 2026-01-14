#ifndef CIPHERFACTORY_H
#define CIPHERFACTORY_H

#include <memory>
#include <stdexcept>

#include "enums.h"
#include "IBlockCipher.h"
#include "aes.h"
#include "des.h"
#include "blowfish.h"
#include "xtea.h"


class CipherFactory {
public:
    static std::unique_ptr<IBlockCipher> createCipher(
        CipherAlgorithm algo,
        int keyBits
        )
    {
        switch (algo) {
        case CipherAlgorithm::AES:
            return std::make_unique<AES>(keyBits);

        case CipherAlgorithm::Blowfish:
            return std::make_unique<Blowfish>(keyBits);

        case CipherAlgorithm::DES:
            return std::make_unique<DES>();

        case CipherAlgorithm::XTEA:
            return std::make_unique<XTEA>();

        default:
            throw std::invalid_argument("Unsupported cipher algorithm");
        }
    }
};

#endif // CIPHERFACTORY_H
