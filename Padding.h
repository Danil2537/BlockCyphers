#ifndef PADDING_H
#define PADDING_H

class Padding {
public:
    static QByteArray addPKCS5(
        const QByteArray& data,
        size_t blockSize
        );

    static QByteArray removePKCS5(
        const QByteArray& data
        );

    static QByteArray zeroPadding(...);
};

#endif // PADDING_H
