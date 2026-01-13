#ifndef FILEENCRYPTIONSERVICE_H
#define FILEENCRYPTIONSERVICE_H

class FileCryptoService {
public:
    static void encryptFile(
        const QString& input,
        const QString& output,
        CipherContext& ctx
        );

    static void decryptFile(...);
};

#endif // FILEENCRYPTIONSERVICE_H
