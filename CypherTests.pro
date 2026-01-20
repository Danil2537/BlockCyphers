QT += core gui widgets testlib
CONFIG += c++17 console

TEMPLATE = app
TARGET = BlockCyphers_tests

SOURCES += \
    test_gui.cpp \
    CipherContext.cpp \
    aes.cpp \
    blowfish.cpp \
    des.cpp \
    mainwindow.cpp \
    padding.cpp \
    xtea.cpp

HEADERS += \
    CipherContext.h \
    CipherFactory.h \
    IBlockCipher.h \
    IMode.h \
    ModeFactory.h \
    Padding.h \
    aes.h \
    blowfish.h \
    blowfish_tables.h \
    des.h \
    enums.h \
    mainwindow.h \
    xtea.h

FORMS += \
    mainwindow.ui
