#ifndef ENUMS_H
#define ENUMS_H

enum class CipherAlgorithm {
    AES,
    DES,
    Blowfish,
    XTEA
};

enum class CipherMode {
    ECB,
    CBC,
    CFB,
    OFB
};

enum class Operation {
    Encrypt,
    Decrypt
};

enum class PaddingType {
    none,
    zero,
    ISO10126,
    PKCS5
};

#endif // ENUMS_H
