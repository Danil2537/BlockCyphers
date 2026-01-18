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

QByteArray MainWindow::readKey() const
{
    QByteArray key = ui->keyTextEdit->toPlainText().toUtf8();
    if (key.isEmpty())
        throw std::runtime_error("Key is empty");

    return key;
}

QByteArray MainWindow::readIV() const
{
    QByteArray iv = ui->IVTextEdit->toPlainText().toUtf8();
    return iv; // may be empty - handled by mode
}

QByteArray MainWindow::readInputData() const
{
    if (ui->isFileCheckbox->isChecked()) {
        QFile file(ui->dataTextEdit->toPlainText());
        if (!file.open(QIODevice::ReadOnly))
            throw std::runtime_error("Cannot open input file");

        return file.readAll();
    }

    return QByteArray::fromBase64(
        ui->dataTextEdit->toPlainText().toUtf8()
        );
}

CipherContext MainWindow::createCipherContext()
{
    int keyBits = ui->keySizeComboBox->currentText().toInt();

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
    int bits = ui->keySizeComboBox->currentText().toInt();
    QByteArray key = KeyGenerator::generateKey(bits);

    ui->keyTextEdit->setText(key.toHex());
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

