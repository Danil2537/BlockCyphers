QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    CipherContext.cpp \
    aes.cpp \
    blowfish.cpp \
    des.cpp \
    main.cpp \
    mainwindow.cpp \
    xtea.cpp

HEADERS += \
    CipherContext.h \
    CipherFactory.h \
    FileEncryptionService.h \
    IBlockCipher.h \
    IMode.h \
    Keygen.h \
    ModeFactory.h \
    Padding.h \
    aes.h \
    blowfish.h \
    blowfish_tables.h \
    cbc.h \
    cfb.h \
    des.h \
    ecb.h \
    enums.h \
    mainwindow.h \
    ofb.h \
    xtea.h

FORMS += \
    mainwindow.ui

TRANSLATIONS += \
    BlockCyphers_uk_UA.ts
CONFIG += lrelease
CONFIG += embed_translations

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

DISTFILES += \
    aes_inv_sbox.inc \
    aes_sbox.inc
