// Copyright (c) 2011-2015 The Bitcoin developers
// Copyright (c) 2016-2018 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/walletview.h>

#include <qt/addressbookpage.h>
#include <qt/askpassphrasedialog.h>
#include <qt/bitcoingui.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/receivecoinsdialog.h>
#include <qt/sendcoinsdialog.h>
#include <qt/signverifymessagedialog.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionview.h>
#include <qt/walletmodel.h>

#include "bip38tooldialog.h"
#include "blockexplorer.h"
#include "masternodeconfig.h"
#include "multisenddialog.h"
#include "multisigdialog.h"
#include "privacydialog.h"

#include <interfaces/node.h>
#include <ui_interface.h>

#include <QAction>
#include <QActionGroup>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QProgressDialog>
#include <QPushButton>
#include <QSettings>
#include <QVBoxLayout>

WalletView::WalletView(const PlatformStyle *_platformStyle, QWidget *parent):
    QStackedWidget(parent),
    clientModel(nullptr),
    walletModel(nullptr),
    platformStyle(_platformStyle)
{
    // Create tabs
    overviewPage = new OverviewPage(platformStyle, this);
    explorerWindow = new BlockExplorer(this);
    transactionsPage = new QWidget(this);

    // Create Header with the same names as the other forms to be CSS-Id compatible
    QFrame *frame_Header = new QFrame(transactionsPage);
    frame_Header->setObjectName(QStringLiteral("frame_Header"));

    QVBoxLayout* verticalLayout_8 = new QVBoxLayout(frame_Header);
    verticalLayout_8->setObjectName(QStringLiteral("verticalLayout_8"));
    verticalLayout_8->setContentsMargins(0, 0, 0, 0);

    QHBoxLayout* horizontalLayout_Header = new QHBoxLayout();
    horizontalLayout_Header->setObjectName(QStringLiteral("horizontalLayout_Header"));

    QLabel* labelOverviewHeaderLeft = new QLabel(frame_Header);
    labelOverviewHeaderLeft->setObjectName(QStringLiteral("labelOverviewHeaderLeft"));
    labelOverviewHeaderLeft->setMinimumSize(QSize(464, 60));
    labelOverviewHeaderLeft->setMaximumSize(QSize(16777215, 60));
    labelOverviewHeaderLeft->setText(tr("HISTORY"));
    QFont fontHeaderLeft;
    fontHeaderLeft.setPointSize(20);
    fontHeaderLeft.setBold(true);
    fontHeaderLeft.setWeight(75);
    labelOverviewHeaderLeft->setFont(fontHeaderLeft);

    horizontalLayout_Header->addWidget(labelOverviewHeaderLeft);
    QSpacerItem* horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);
    horizontalLayout_Header->addItem(horizontalSpacer_3);

    QLabel* labelOverviewHeaderRight = new QLabel(frame_Header);
    labelOverviewHeaderRight->setObjectName(QStringLiteral("labelOverviewHeaderRight"));
    labelOverviewHeaderRight->setMinimumSize(QSize(464, 60));
    labelOverviewHeaderRight->setMaximumSize(QSize(16777215, 60));
    labelOverviewHeaderRight->setText(QString());
    QFont fontHeaderRight;
    fontHeaderRight.setPointSize(14);
    labelOverviewHeaderRight->setFont(fontHeaderRight);
    labelOverviewHeaderRight->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

    horizontalLayout_Header->addWidget(labelOverviewHeaderRight);
    horizontalLayout_Header->setStretch(0, 1);
    horizontalLayout_Header->setStretch(2, 1);
    verticalLayout_8->addLayout(horizontalLayout_Header);

    QVBoxLayout* vbox = new QVBoxLayout();
    QHBoxLayout* hbox_buttons = new QHBoxLayout();
    vbox->addWidget(frame_Header);

    transactionView = new TransactionView(platformStyle, this);
    vbox->addWidget(transactionView);
    QPushButton* exportButton = new QPushButton(tr("&Export"), this);
    exportButton->setToolTip(tr("Export the data in the current tab to a file"));
#ifndef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    exportButton->setIcon(QIcon(":/icons/export"));
#endif
    hbox_buttons->addStretch();

    // Sum of selected transactions
    QLabel* transactionSumLabel = new QLabel();                // Label
    transactionSumLabel->setObjectName("transactionSumLabel"); // Label ID as CSS-reference
    transactionSumLabel->setText(tr("Selected amount:"));
    hbox_buttons->addWidget(transactionSumLabel);

    transactionSum = new QLabel();                   // Amount
    transactionSum->setObjectName("transactionSum"); // Label ID as CSS-reference
    transactionSum->setMinimumSize(200, 8);
    transactionSum->setTextInteractionFlags(Qt::TextSelectableByMouse);
    hbox_buttons->addWidget(transactionSum);

    hbox_buttons->addWidget(exportButton);
    vbox->addLayout(hbox_buttons);
    transactionsPage->setLayout(vbox);

    privacyPage = new PrivacyDialog(platformStyle, this);
    receiveCoinsPage = new ReceiveCoinsDialog(platformStyle, this);
    sendCoinsPage = new SendCoinsDialog(platformStyle, this);

    addWidget(overviewPage);
    addWidget(transactionsPage);
    addWidget(privacyPage);
    addWidget(receiveCoinsPage);
    addWidget(sendCoinsPage);
    addWidget(explorerWindow);

    QSettings settings;
    if (settings.value("fShowMasternodesTab").toBool()) {
        masternodeListPage = new MasternodeList();
        addWidget(masternodeListPage);
    }

    // Clicking on a transaction on the overview pre-selects the transaction on the transaction history page
    connect(overviewPage, &OverviewPage::transactionClicked, transactionView, static_cast<void (TransactionView::*)(const QModelIndex&)>(&TransactionView::focusTransaction));

    connect(overviewPage, &OverviewPage::outOfSyncWarningClicked, this, &WalletView::requestedSyncWarningInfo);

    // Double-clicking on a transaction on the transaction history page shows details
    connect(transactionView, SIGNAL(doubleClicked(QModelIndex)), transactionView, SLOT(showDetails()));

    // Update wallet with sum of selected transactions
    connect(transactionView, SIGNAL(trxAmount(QString)), this, SLOT(trxAmount(QString)));

    // Highlight transaction after send
//    connect(sendCoinsPage, &SendCoinsDialog::coinsSent, transactionView, static_cast<void (TransactionView::*)(const uint256&)>(&TransactionView::focusTransaction));

    // Clicking on "Export" allows to export the transaction list
    connect(exportButton, &QPushButton::clicked, transactionView, &TransactionView::exportClicked);

    // Pass through messages from sendCoinsPage
    connect(sendCoinsPage, &SendCoinsDialog::message, this, &WalletView::message);
    // Pass through messages from transactionView
    connect(transactionView, &TransactionView::message, this, &WalletView::message);
}

WalletView::~WalletView()
{
}

void WalletView::setBitcoinGUI(BitcoinGUI *gui)
{
    if (gui)
    {
        // Clicking on a transaction on the overview page simply sends you to transaction history page
        connect(overviewPage, &OverviewPage::transactionClicked, gui, &BitcoinGUI::gotoHistoryPage);

        // Navigate to transaction history page after send
        connect(sendCoinsPage, &SendCoinsDialog::coinsSent, gui, &BitcoinGUI::gotoHistoryPage);

        // Receive and report messages
        connect(this, &WalletView::message, [gui](const QString &title, const QString &message, unsigned int style) {
            gui->message(title, message, style);
        });

        // Pass through encryption status changed signals
        connect(this, &WalletView::encryptionStatusChanged, gui, &BitcoinGUI::updateWalletStatus);

        // Pass through transaction notifications
        connect(this, &WalletView::incomingTransaction, gui, &BitcoinGUI::incomingTransaction);

        // Connect HD enabled state signal
        connect(this, &WalletView::hdEnabledStatusChanged, gui, &BitcoinGUI::updateWalletStatus);
    }
}

void WalletView::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    overviewPage->setClientModel(_clientModel);
    sendCoinsPage->setClientModel(_clientModel);
    QSettings settings;
    if (settings.value("fShowMasternodesTab").toBool()) {
        masternodeListPage->setClientModel(_clientModel);
    }
}

void WalletView::setWalletModel(WalletModel *_walletModel)
{
    this->walletModel = _walletModel;

    // Put transaction list in tabs
    transactionView->setModel(_walletModel);
    overviewPage->setWalletModel(_walletModel);
    QSettings settings;
    if (settings.value("fShowMasternodesTab").toBool()) {
        masternodeListPage->setWalletModel(_walletModel);
    }
    privacyPage->setModel(_walletModel);
    receiveCoinsPage->setModel(_walletModel);
    sendCoinsPage->setModel(_walletModel);

    if (_walletModel)
    {
        // Receive and pass through messages from wallet model
        connect(_walletModel, &WalletModel::message, this, &WalletView::message);

        // Handle changes in encryption status
        connect(_walletModel, &WalletModel::encryptionStatusChanged, this, &WalletView::encryptionStatusChanged);
        updateEncryptionStatus();

        // update HD status
        Q_EMIT hdEnabledStatusChanged();

        // Balloon pop-up for new transaction
        connect(_walletModel->getTransactionTableModel(), &TransactionTableModel::rowsInserted, this, &WalletView::processNewTransaction);

        // Ask for passphrase if needed
        connect(_walletModel, &WalletModel::requireUnlock, this, &WalletView::unlockWallet);

        // Show progress dialog
        connect(_walletModel, &WalletModel::showProgress, this, &WalletView::showProgress);
    }
}

void WalletView::processNewTransaction(const QModelIndex& parent, int start, int /*end*/)
{
    // Prevent balloon-spam when initial block download is in progress
    if (!walletModel || !clientModel || clientModel->node().isInitialBlockDownload())
        return;

    TransactionTableModel *ttm = walletModel->getTransactionTableModel();
    if (!ttm || ttm->processingQueuedTransactions())
        return;

    QString date = ttm->index(start, TransactionTableModel::Date, parent).data().toString();
    qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent).data(Qt::EditRole).toULongLong();
    QString type = ttm->index(start, TransactionTableModel::Type, parent).data().toString();
    QModelIndex index = ttm->index(start, 0, parent);
    QString address = ttm->data(index, TransactionTableModel::AddressRole).toString();
    QString label = ttm->data(index, TransactionTableModel::LabelRole).toString();

    Q_EMIT incomingTransaction(date, walletModel->getOptionsModel()->getDisplayUnit(), amount, type, address, label, walletModel->getWalletName());
}

void WalletView::gotoOverviewPage()
{
    setCurrentWidget(overviewPage);
}

void WalletView::gotoHistoryPage()
{
    setCurrentWidget(transactionsPage);
}


void WalletView::gotoBlockExplorerPage()
{
    setCurrentWidget(explorerWindow);
}

void WalletView::gotoMasternodePage()
{
    QSettings settings;
    if (settings.value("fShowMasternodesTab").toBool()) {
        setCurrentWidget(masternodeListPage);
    }
}

void WalletView::gotoReceiveCoinsPage()
{
    setCurrentWidget(receiveCoinsPage);
}

void WalletView::gotoPrivacyPage()
{
    setCurrentWidget(privacyPage);
}

void WalletView::gotoSendCoinsPage(QString addr)
{
    setCurrentWidget(sendCoinsPage);

    if (!addr.isEmpty())
        sendCoinsPage->setAddress(addr);
}

void WalletView::gotoSignMessageTab(QString addr)
{
    // calls show() in showTab_SM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_SM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_SM(addr);
}

void WalletView::gotoVerifyMessageTab(QString addr)
{
    // calls show() in showTab_VM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_VM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_VM(addr);
}

void WalletView::gotoBip38Tool()
{
    Bip38ToolDialog* bip38ToolDialog = new Bip38ToolDialog(platformStyle, this);
    //bip38ToolDialog->setAttribute(Qt::WA_DeleteOnClose);
    bip38ToolDialog->setModel(walletModel);
    bip38ToolDialog->showTab_ENC(true);
}

void WalletView::gotoMultiSendDialog()
{
    MultiSendDialog* multiSendDialog = new MultiSendDialog(platformStyle, this);
    multiSendDialog->setModel(walletModel);
    multiSendDialog->show();
}

void WalletView::gotoMultisigDialog(int index)
{
    MultisigDialog* multisig = new MultisigDialog(platformStyle, this);
    multisig->setModel(walletModel);
    multisig->showTab(index);
}

bool WalletView::handlePaymentRequest(const SendCoinsRecipient& recipient)
{
    return sendCoinsPage->handlePaymentRequest(recipient);
}

void WalletView::showOutOfSyncWarning(bool fShow)
{
    overviewPage->showOutOfSyncWarning(fShow);
    privacyPage->showOutOfSyncWarning(fShow);
}

void WalletView::updateEncryptionStatus()
{
    Q_EMIT encryptionStatusChanged();
}

void WalletView::encryptWallet(bool status)
{
    if(!walletModel)
        return;
    AskPassphraseDialog dlg(status ? AskPassphraseDialog::Mode::Encrypt : AskPassphraseDialog::Mode::Decrypt, this, 
                            walletModel, AskPassphraseDialog::Context::Encrypt);
//    dlg.setModel(walletModel);
    dlg.exec();

    updateEncryptionStatus();
}

void WalletView::backupWallet()
{
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Backup Wallet"), QString(),
        tr("Wallet Data (*.dat)"), nullptr);

    if (filename.isEmpty())
        return;

    if (!walletModel->wallet().backupWallet(filename.toLocal8Bit().data())) {
        Q_EMIT message(tr("Backup Failed"), tr("There was an error trying to save the wallet data to %1.").arg(filename),
            CClientUIInterface::MSG_ERROR);
        }
    else {
        Q_EMIT message(tr("Backup Successful"), tr("The wallet data was successfully saved to %1.").arg(filename),
            CClientUIInterface::MSG_INFORMATION);
    }
}

void WalletView::changePassphrase()
{
    AskPassphraseDialog dlg(AskPassphraseDialog::Mode::ChangePass, this, walletModel, AskPassphraseDialog::Context::ChangePass);
    dlg.exec();
}

void WalletView::unlockWallet(AskPassphraseDialog::Context context)
{
    if (!walletModel)
        return;
    // Unlock wallet when requested by wallet model

    if (walletModel->getEncryptionStatus() == WalletModel::Locked || walletModel->getEncryptionStatus() == WalletModel::UnlockedForAnonymizationOnly) {
        AskPassphraseDialog dlg(AskPassphraseDialog::Mode::UnlockAnonymize, this, walletModel, context);
        dlg.exec();
    }
}

void WalletView::lockWallet()
{
    if (!walletModel)
        return;

    walletModel->setWalletLocked(true);
}

void WalletView::toggleLockWallet()
{
    if (!walletModel)
        return;

    WalletModel::EncryptionStatus encStatus = walletModel->getEncryptionStatus();

    // Unlock the wallet when requested
    if (encStatus == walletModel->Locked) {
        AskPassphraseDialog dlg(AskPassphraseDialog::Mode::UnlockAnonymize, this, walletModel, AskPassphraseDialog::Context::ToggleLock);
        dlg.exec();
    }

    else if (encStatus == walletModel->Unlocked || encStatus == walletModel->UnlockedForAnonymizationOnly) {
            walletModel->setWalletLocked(true);
    }
}

void WalletView::usedSendingAddresses()
{
    if (!walletModel)
        return;
    AddressBookPage* dlg = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::SendingTab, this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setModel(walletModel->getAddressTableModel());
    dlg->show();
}

void WalletView::usedReceivingAddresses()
{
    if (!walletModel)
        return;
    AddressBookPage* dlg = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::ReceivingTab, this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setModel(walletModel->getAddressTableModel());
    dlg->show();
}

void WalletView::showProgress(const QString& title, int nProgress)
{
    if (nProgress == 0) {
        progressDialog = new QProgressDialog(title, tr("Cancel"), 0, 100);
        GUIUtil::PolishProgressDialog(progressDialog);
        progressDialog->setWindowModality(Qt::ApplicationModal);
        progressDialog->setMinimumDuration(0);
        progressDialog->setAutoClose(false);
        progressDialog->setValue(0);
    } else if (nProgress == 100) {
        if (progressDialog) {
            progressDialog->close();
            progressDialog->deleteLater();
        }
    } else if (progressDialog) {
        if (progressDialog->wasCanceled()) {
            getWalletModel()->wallet().abortRescan();
        } else {
            progressDialog->setValue(nProgress);
        }
    }
}

/** Update wallet with the sum of the selected transactions */
void WalletView::trxAmount(QString amount)
{
    transactionSum->setText(amount);
}

void WalletView::requestedSyncWarningInfo()
{
    Q_EMIT outOfSyncWarningClicked();
}
