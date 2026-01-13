#ifndef CFB_H
#define CFB_H

#include "imode.h"

class CFB: public IMode {
    QByteArray iv;

public:

    explicit CFB(){}

    void setIV(const QByteArray& iv_) override {
        iv = iv_;
    }

    QByteArray process(
        IBlockCipher& cipher,
        const QByteArray& data,
        Operation op
        ) override{}
};

#endif // CFB_H
