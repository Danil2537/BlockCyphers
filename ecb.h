#ifndef ECB_H
#define ECB_H
#include "IMode.h"
class ECB : public IMode{
public:
    explicit ECB(){}
    void setIV(const QByteArray&) override {}

    QByteArray process(
        IBlockCipher& cipher,
        const QByteArray& data,
        Operation op
        ) override{}
};

#endif // ECB_H
