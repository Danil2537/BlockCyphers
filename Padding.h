#ifndef PADDING_H
#define PADDING_H
#include<QByteArray>
class Padding {
public:
    // static QByteArray addPKCS5(
    //     const QByteArray& data,
    //     size_t blockSize
    //     );

    // static QByteArray removePKCS5(
    //     const QByteArray& data
    //     );

    // static QByteArray zeroPadding(...);

    static QByteArray addPKCS5(const QByteArray& data, size_t blockSize);
    static QByteArray removePKCS5(const QByteArray& data);
    static QByteArray addZeroPadding(const QByteArray& data, size_t blockSize);
    static QByteArray removeZeroPadding(const QByteArray& data);
    static QByteArray addISO10126(const QByteArray& data, size_t blockSize);
    static QByteArray removeISO10126(const QByteArray& data);
};

#endif // PADDING_H
