#ifndef IMODE_H
#define IMODE_H
#include<QByteArray>
#include <iostream>
#include "enums.h"
#include "IBlockCipher.h"
class IMode
{
public:
    virtual ~IMode() = default;

    virtual void setIV(const QByteArray& iv) = 0;

    virtual QByteArray process(
        IBlockCipher& cipher,
        const QByteArray& data,
        Operation op
        ) = 0;
};

#endif // IMODE_H
