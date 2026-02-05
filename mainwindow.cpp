#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QClipboard>
#include <QFileDialog>
#include "keygen.h"
#include "enums.h"
#include "CipherContext.h"
 #include "CipherFactory.h"
 #include "ModeFactory.h"
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->algorithmComboBox, &QComboBox::currentTextChanged,
            this, &MainWindow::updateAllowedSizes);
    connect(ui->modeComboBox, &QComboBox::currentTextChanged,
            this, &MainWindow::updateAllowedSizes);

    // Call once at startup
    updateAllowedSizes();
}

MainWindow::~MainWindow()
{
    delete ui;
}

// CipherAlgorithm MainWindow::selectedAlgorithm() const
// {
//     const QString text = ui->algorithmComboBox->currentText();

//     if (text == "AES") return CipherAlgorithm::AES;
//     if (text == "DES") return CipherAlgorithm::DES;
//     if (text == "Blowfish") return CipherAlgorithm::Blowfish;
//     if (text == "XTEA") return CipherAlgorithm::XTEA;

//     throw std::runtime_error(tr("Unknown algorithm").toStdString());
// }

void MainWindow::updateAllowedSizes()
{
    CipherAlgorithm algo = selectedAlgorithm();
    CipherMode mode = selectedMode();

    int defaultKeySize = 128;

    // Set the allowed key size as a single number
    switch(algo) {
    case CipherAlgorithm::AES:
        defaultKeySize = 128; // pick 128 as default
        break;
    case CipherAlgorithm::Blowfish:
        defaultKeySize = 128; // can be any 32–448, pick default
        break;
    case CipherAlgorithm::DES:
        defaultKeySize = 56;
        break;
    case CipherAlgorithm::XTEA:
        defaultKeySize = 128;
        break;
    }

    ui->allowedKeySizeLabel->setText(QString::number(defaultKeySize));

    // IV sizes
    int blockSize = 0;
    switch(algo) {
    case CipherAlgorithm::AES: blockSize = 128; break;
    case CipherAlgorithm::Blowfish: blockSize = 64; break;
    case CipherAlgorithm::DES: blockSize = 64; break;
    case CipherAlgorithm::XTEA: blockSize = 64; break;
    }
    ui->allowedIVSizeLabel->setText(mode == CipherMode::ECB ? "0" : QString::number(blockSize));

    // // Message size info
    // ui->allowedMsgSizeLabel->setText(
    //     QString("Any size").arg(blockSize)
    //     );
}


CipherAlgorithm MainWindow::selectedAlgorithm() const
{
    QString id = ui->algorithmComboBox->currentData().toString();
    if (id.isEmpty())
        id = ui->algorithmComboBox->currentText();

    if (id == "AES") return CipherAlgorithm::AES;
    if (id == "DES") return CipherAlgorithm::DES;
    if (id == "Blowfish") return CipherAlgorithm::Blowfish;
    if (id == "XTEA") return CipherAlgorithm::XTEA;

    throw std::runtime_error("Unknown algorithm");
}

CipherMode MainWindow::selectedMode() const
{
    const QString text = ui->modeComboBox->currentText();

    if (text == "ECB") return CipherMode::ECB;
    if (text == "CBC") return CipherMode::CBC;
    if (text == "CFB") return CipherMode::CFB;
    if (text == "OFB") return CipherMode::OFB;

    throw std::runtime_error("Unknown mode");
}

PaddingType MainWindow::selectedPadding() const
{
    const QString text = ui->paddingComboBox->currentText();

    if (text == "No Padding") return PaddingType::none;
    if (text == "Zero Padding") return PaddingType::zero;
    if (text == "ISO 10126") return PaddingType::ISO10126;
    if (text == "PKCS5") return PaddingType::PKCS5;

    throw std::runtime_error("Unknown padding");
}

void MainWindow::on_copyKeyButton_clicked()
{
    QString keyInput = ui->keyTextEdit->toPlainText();
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(keyInput);
}


void MainWindow::on_resultCopyButton_clicked()
{
    QString resultOutput = ui->resultTextBrowser->toPlainText();
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(resultOutput);
}


void MainWindow::on_chooseInputFileButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this,
                                                    tr("Choose file to encrypt"),
                                                    "../../../",
                                                    tr("*"));
    ui->dataTextEdit->setText(fileName);
}


void MainWindow::on_resultFilePickButton_clicked()
{
    // Source - https://stackoverflow.com/a
    // Posted by liuyanghejerry
    // Retrieved 2026-01-06, License - CC BY-SA 3.0

    QString dir = QFileDialog::getExistingDirectory(this, tr("Open Directory"),
                                                    ".",
                                                    QFileDialog::ShowDirsOnly
                                                        | QFileDialog::DontResolveSymlinks);
    ui->resultTextBrowser->setText(dir);
}

// QByteArray MainWindow::readKey() const
// {
//     QByteArray key = ui->keyTextEdit->toPlainText().toUtf8();
//     if (key.isEmpty())
//         throw std::runtime_error("Key is empty");

//     return key;
// }

// QByteArray MainWindow::readIV() const
// {
//     QByteArray iv = ui->IVTextEdit->toPlainText().toUtf8();
//     return iv; // may be empty - handled by mode
// }

// QByteArray MainWindow::readInputData() const
// {
//     if (ui->isFileCheckbox->isChecked()) {
//         QFile file(ui->dataTextEdit->toPlainText());
//         if (!file.open(QIODevice::ReadOnly))
//             throw std::runtime_error("Cannot open input file");

//         return file.readAll();
//     }

//     // return QByteArray::fromBase64(
//     //     ui->dataTextEdit->toPlainText().toUtf8()
//     //     );
//     return ui->dataTextEdit->toPlainText().toUtf8();
// }

QByteArray MainWindow::readKey() const
{
    QByteArray key = ui->keyTextEdit->toPlainText().toUtf8();
    if (key.isEmpty())
        throw std::runtime_error("Key is empty");

    // Check allowed key length
    CipherAlgorithm algo = selectedAlgorithm();
    int keyBits = key.size() * 8;

    bool valid = false;
    switch(algo) {
    case CipherAlgorithm::AES:
        valid = (keyBits == 128 || keyBits == 192 || keyBits == 256);
        break;
    case CipherAlgorithm::Blowfish:
        valid = (keyBits >= 32 && keyBits <= 448);
        break;
    case CipherAlgorithm::DES:
        valid = (keyBits == 56);
        break;
    case CipherAlgorithm::XTEA:
        valid = (keyBits == 128);
        break;
    }

    if (!valid)
        throw std::runtime_error("Key length invalid for selected algorithm");

    return key;
}

QByteArray MainWindow::readIV() const
{
    QByteArray iv = ui->IVTextEdit->toPlainText().toUtf8();

    CipherMode mode = selectedMode();
    if (mode == CipherMode::ECB) return QByteArray(); // no IV

    CipherAlgorithm algo = selectedAlgorithm();
    int blockSize = 0;
    switch(algo) {
    case CipherAlgorithm::AES: blockSize = 128; break;
    case CipherAlgorithm::Blowfish: blockSize = 64; break;
    case CipherAlgorithm::DES: blockSize = 64; break;
    case CipherAlgorithm::XTEA: blockSize = 64; break;
    }

    if (iv.size() * 8 != blockSize)
        throw std::runtime_error(
            QString("IV must be %1 bits").arg(blockSize).toStdString()
            );

    return iv;
}

QByteArray MainWindow::readInputData() const
{
    QByteArray data;
    if (ui->isFileCheckbox->isChecked()) {
        QFile file(ui->dataTextEdit->toPlainText());
        if (!file.open(QIODevice::ReadOnly))
            throw std::runtime_error("Cannot open input file");
        data = file.readAll();
    } else {
        data = ui->dataTextEdit->toPlainText().toUtf8();
    }

    if (data.isEmpty())
        throw std::runtime_error("Message cannot be empty");

    return data;
}

CipherContext MainWindow::createCipherContext()
{
    //int keyBits = ui->keySizeComboBox->currentText().toInt();
    int keyBits = ui->allowedKeySizeLabel->text().toInt();
    auto cipher = CipherFactory::createCipher(
        selectedAlgorithm(),
        keyBits
        );

    auto mode = ModeFactory::createMode(
        selectedMode()
        );

    CipherContext ctx(std::move(cipher), std::move(mode));
    ctx.setKey(readKey());

    QByteArray iv = readIV();
    if (!iv.isEmpty())
        ctx.setIV(iv);

    ctx.setPadding(selectedPadding());

    return ctx;
}

void MainWindow::on_generateKeyButton_clicked()
{
    int bits = ui->allowedKeySizeLabel->text().toInt();
    QByteArray key = KeyGenerator::generateKey(bits);

    ui->keyTextEdit->setText(key);
}


void MainWindow::on_encryptButton_clicked()
{
    try {
        CipherContext ctx = createCipherContext();
        QByteArray input = readInputData();

        QByteArray encrypted = ctx.encrypt(input);

        if (ui->isFileCheckbox->isChecked()) {
            QString outputDir = ui->resultTextBrowser->toPlainText();
            QFile out(outputDir + "/encrypted.bin");

            if (!out.open(QIODevice::WriteOnly))
                throw std::runtime_error("Cannot write output file");

            out.write(encrypted);
        } else {
            ui->resultTextBrowser->setText(
                encrypted.toBase64()
                );
        }

       statusBar()->showMessage(tr("Encryption successful"));
    }
    catch (const std::exception& e) {
        QMessageBox::critical(this,
                              tr("Encryption error"),
                              e.what());
    }
}


void MainWindow::on_decryptButton_clicked()
{
    try {
        CipherContext ctx = createCipherContext();
        QByteArray input;

        if (ui->isFileCheckbox->isChecked()) {
            input = readInputData();
        } else {
            input = QByteArray::fromBase64(
                ui->dataTextEdit->toPlainText().toUtf8()
                );
        }

        QByteArray decrypted = ctx.decrypt(input);

        if (ui->isFileCheckbox->isChecked()) {
            QString outputDir = ui->resultTextBrowser->toPlainText();
            QFile out(outputDir + "/decrypted.out");

            if (!out.open(QIODevice::WriteOnly))
                throw std::runtime_error("Cannot write output file");

            out.write(decrypted);
        } else {
            ui->resultTextBrowser->setText(
                QString::fromUtf8(decrypted)
                );

            //ui->resultTextBrowser->setText(decrypted.toBase64());
        }

        statusBar()->showMessage("Decryption successful");
    }
    catch (const std::exception& e) {
        QMessageBox::critical(this, "Decryption error", e.what());
    }
}

