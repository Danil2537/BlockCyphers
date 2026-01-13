#ifndef MODEFACTORY_H
#define MODEFACTORY_H

#include <memory>
#include <stdexcept>

#include "IMode.h"
#include "enums.h"

#include "ecb.h"
#include "cbc.h"
#include "cfb.h"
#include "ofb.h"

class ModeFactory {
public:
    static std::unique_ptr<IMode> createMode(CipherMode mode)
    {
        switch (mode) {
        case CipherMode::ECB:
            return std::make_unique<ECB>();

        case CipherMode::CBC:
            return std::make_unique<CBC>();

        case CipherMode::CFB:
            return std::make_unique<CFB>();

        case CipherMode::OFB:
            return std::make_unique<OFB>();

        default:
            throw std::invalid_argument("Unsupported cipher mode");
        }
    }
};

#endif // MODEFACTORY_H
