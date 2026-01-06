#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QClipboard>
#include <QFileDialog>
#include "keygen.h"

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
                                                    ".",
                                                    tr("Any File"));
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


void MainWindow::on_generateKeyButton_clicked()
{
    ui->keyTextEdit->setText(
        Keygen::Generate(
            ui->keySizeComboBox->currentText().toInt()
            )
        );
}


void MainWindow::on_encryptButton_clicked()
{
    //TODO: implement the call to Encrypt
}


void MainWindow::on_decryptButton_clicked()
{
    //TODO: implement the call to decrypt
}

