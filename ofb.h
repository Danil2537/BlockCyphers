#ifndef OFB_H
#define OFB_H


#include "IMode.h"
class OFB : public IMode{
public:
    explicit OFB(){}
    void setIV(const QByteArray&) override {}

    QByteArray process(
        IBlockCipher& cipher,
        const QByteArray& data,
        Operation op
        ) override{}
};

#endif // OFB_H
