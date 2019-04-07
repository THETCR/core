// Copyright (c) 2011-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/wispr-config.h>
#endif

#include <qt/walletmodel.h>

#include <qt/addresstablemodel.h>
#include <qt/guiconstants.h>
#include <qt/optionsmodel.h>
#include <qt/paymentserver.h>
#include <qt/recentrequeststablemodel.h>
#include <qt/sendcoinsdialog.h>
#include <qt/transactiontablemodel.h>

#include <interfaces/handler.h>
#include <interfaces/node.h>
#include <key_io.h>
#include <ui_interface.h>
#include <util/system.h> // for GetBoolArg
#include <wallet/coincontrol.h>
#include <wallet/wallet.h>

#include <stdint.h>

#include <spork.h>

#include <QDebug>
#include <QMessageBox>
#include <QSet>
#include <QTimer>


WalletModel::WalletModel(std::unique_ptr<interfaces::Wallet> wallet, interfaces::Node& node, const PlatformStyle *platformStyle, OptionsModel *_optionsModel, QObject *parent) :
    QObject(parent), m_wallet(std::move(wallet)), m_node(node), optionsModel(_optionsModel), addressTableModel(nullptr),
    transactionTableModel(nullptr),
    recentRequestsTableModel(nullptr),
    cachedEncryptionStatus(Unencrypted),
    cachedNumBlocks(0)
{
    std::cout << "haveWatchOnly\n";
    fHaveWatchOnly = m_wallet->haveWatchOnly();
    std::cout << "fHaveMultiSig\n";
    fHaveMultiSig = m_wallet->haveMultiSig();

    std::cout << "addressTableModel\n";
    addressTableModel = new AddressTableModel(this);
    std::cout << "transactionTableModel\n";
    transactionTableModel = new TransactionTableModel(platformStyle, this);
    std::cout << "recentRequestsTableModel\n";
    recentRequestsTableModel = new RecentRequestsTableModel(this);
    std::cout << "pollTimer\n";

    // This timer will be fired repeatedly to update the balance
    pollTimer = new QTimer(this);
    connect(pollTimer, &QTimer::timeout, this, &WalletModel::pollBalanceChanged);
    pollTimer->start(MODEL_UPDATE_DELAY);

    subscribeToCoreSignals();
}

WalletModel::~WalletModel()
{
    unsubscribeFromCoreSignals();
}

CAmount WalletModel::getLockedBalance() const
{
    return m_wallet->getLockedCoins();
}

void WalletModel::updateStatus()
{
    EncryptionStatus newEncryptionStatus = getEncryptionStatus();

    if(cachedEncryptionStatus != newEncryptionStatus) {
        Q_EMIT encryptionStatusChanged();
    }
}

void WalletModel::pollBalanceChanged()
{
    // Try to get balances and return early if locks can't be acquired. This
    // avoids the GUI from getting stuck on periodical polls if the core is
    // holding the locks for a longer time - for example, during a wallet
    // rescan.
    interfaces::WalletBalances new_balances;
    int numBlocks = -1;
    if (!m_wallet->tryGetBalances(new_balances, numBlocks)) {
        return;
    }

    if(fForceCheckBalanceChanged || m_node.getNumBlocks() != cachedNumBlocks || nZeromintPercentage != cachedZeromintPercentage || cachedTxLocks != nCompleteTXLocks)
    {
        fForceCheckBalanceChanged = false;

        // Balance and number of transactions might have changed
        cachedNumBlocks = m_node.getNumBlocks();
        cachedZeromintPercentage = nZeromintPercentage;

        checkBalanceChanged(new_balances);
        if(transactionTableModel)
            transactionTableModel->updateConfirmations();
    }
}

void WalletModel::checkBalanceChanged(const interfaces::WalletBalances& new_balances)
{
    if(new_balances.balanceChanged(m_cached_balances)) {
        if (cachedTxLocks != nCompleteTXLocks ) {
            cachedTxLocks = nCompleteTXLocks;
        }
        m_cached_balances = new_balances;
        Q_EMIT balanceChanged(new_balances);
    }
}

void WalletModel::updateTransaction()
{
    // Balance and number of transactions might have changed
    fForceCheckBalanceChanged = true;
}

void WalletModel::updateAddressBook(const QString &address, const QString &label,
        bool isMine, const QString &purpose, int status)
{
    if(addressTableModel)
        addressTableModel->updateEntry(address, label, isMine, purpose, status);
}
void WalletModel::updateAddressBook(const QString &pubCoin, const QString &isUsed, int status)
{
    if(addressTableModel)
        addressTableModel->updateEntry(pubCoin, isUsed, status);
}


void WalletModel::updateWatchOnlyFlag(bool fHaveWatchonly)
{
    fHaveWatchOnly = fHaveWatchonly;
    Q_EMIT notifyWatchonlyChanged(fHaveWatchonly);
}

void WalletModel::updateMultiSigFlag(bool fHaveMultisig)
{
    fHaveMultiSig = fHaveMultisig;
    Q_EMIT notifyMultiSigChanged(fHaveMultiSig);
}

bool WalletModel::validateAddress(const QString &address)
{
    return IsValidDestinationString(address.toStdString());
}

void WalletModel::updateAddressBookLabels(const CTxDestination& dest, const std::string& strName, const std::string& strPurpose)
{
    // Check if we have a new address or an updated label
    std::string name;
    if (!m_wallet->getAddress(
        dest, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr))
    {
        m_wallet->setAddressBook(dest, strName, "send");
    }
    else if (name != strName)
    {
        m_wallet->setAddressBook(dest, strName, ""); // "" means don't change purpose
    }
}

WalletModel::SendCoinsReturn WalletModel::prepareTransaction(WalletModelTransaction &transaction, const CCoinControl& coinControl)
{
    CAmount total = 0;
    bool fSubtractFeeFromAmount = false;
    QList<SendCoinsRecipient> recipients = transaction.getRecipients();
    std::vector<CRecipient> vecSend;

    if(recipients.empty())
    {
        return OK;
    }

    if (isAnonymizeOnlyUnlocked()) {
        return AnonymizeOnlyUnlocked;
    }

    QSet<QString> setAddress; // Used to detect duplicates
    int nAddresses = 0;

    // Pre-check input data for validity
    for (const SendCoinsRecipient &rcp : recipients)
    {
        if (rcp.fSubtractFeeFromAmount)
            fSubtractFeeFromAmount = true;

#ifdef ENABLE_BIP70
        if (rcp.paymentRequest.IsInitialized())
        {   // PaymentRequest...
            CAmount subtotal = 0;
            const payments::PaymentDetails& details = rcp.paymentRequest.getDetails();
            for (int i = 0; i < details.outputs_size(); i++)
            {
                const payments::Output& out = details.outputs(i);
                if (out.amount() <= 0) continue;
                subtotal += out.amount();
                const unsigned char* scriptStr = (const unsigned char*)out.script().data();
                CScript scriptPubKey(scriptStr, scriptStr+out.script().size());
                CAmount nAmount = out.amount();
                CRecipient recipient = {scriptPubKey, nAmount, rcp.fSubtractFeeFromAmount};
                vecSend.push_back(recipient);
            }
            if (subtotal <= 0)
            {
                return InvalidAmount;
            }
            total += subtotal;
        }
        else
#endif
        {   // User-entered bitcoin address / amount:
            if(!validateAddress(rcp.address))
            {
                return InvalidAddress;
            }
            if(rcp.amount <= 0)
            {
                return InvalidAmount;
            }
            setAddress.insert(rcp.address);
            ++nAddresses;

            CScript scriptPubKey = GetScriptForDestination(DecodeDestination(rcp.address.toStdString()));
            CRecipient recipient = {scriptPubKey, rcp.amount, rcp.fSubtractFeeFromAmount};
            vecSend.push_back(recipient);

            total += rcp.amount;
        }
    }
    if(setAddress.size() != nAddresses)
    {
        return DuplicateAddress;
    }

    CAmount nBalance = m_wallet->getAvailableBalance(coinControl);

    if(total > nBalance)
    {
        return AmountExceedsBalance;
    }

    {
        CAmount nFeeRequired = 0;
        int nChangePosRet = -1;
        std::string strFailReason;

        auto& newTx = transaction.getWtx();

        if (recipients[0].useSwiftTX && total > GetSporkValue(SPORK_5_MAX_VALUE) * COIN) {
            Q_EMIT message(tr("Send Coins"), tr("SwiftX doesn't support sending values that high yet. Transactions are currently limited to %1 WSP.").arg(GetSporkValue(SPORK_5_MAX_VALUE)),
                           CClientUIInterface::MSG_ERROR);
            return TransactionCreationFailed;
        }

        newTx = m_wallet->createTransaction(vecSend, coinControl, true /* sign */, nChangePosRet, nFeeRequired, strFailReason, recipients[0].inputType, recipients[0].useSwiftTX);
        transaction.setTransactionFee(nFeeRequired);

        if (recipients[0].useSwiftTX && newTx->get().GetValueOut() > GetSporkValue(SPORK_5_MAX_VALUE) * COIN) {
            Q_EMIT message(tr("Send Coins"), tr("SwiftX doesn't support sending values that high yet. Transactions are currently limited to %1 WSP.").arg(GetSporkValue(SPORK_5_MAX_VALUE)),
                           CClientUIInterface::MSG_ERROR);
            return TransactionCreationFailed;
        }

        if (fSubtractFeeFromAmount && newTx)
            transaction.reassignAmounts(nChangePosRet);

        if(!newTx)
        {
            if(!fSubtractFeeFromAmount && (total + nFeeRequired) > nBalance)
            {
                return SendCoinsReturn(AmountWithFeeExceedsBalance);
            }
            Q_EMIT message(tr("Send Coins"), QString::fromStdString(strFailReason),
                         CClientUIInterface::MSG_ERROR);
            return TransactionCreationFailed;
        }

        // reject absurdly high fee. (This can never happen because the
        // wallet caps the fee at maxTxFee. This merely serves as a
        // belt-and-suspenders check)
        if (nFeeRequired > m_node.getMaxTxFee())
            return AbsurdFee;
    }

    return SendCoinsReturn(OK);
}

WalletModel::SendCoinsReturn WalletModel::sendCoins(WalletModelTransaction &transaction)
{
    QByteArray transaction_array; /* store serialized transaction */

    {
        QList<SendCoinsRecipient> recipients = transaction.getRecipients();
        std::vector<std::pair<std::string, std::string>> vOrderForm;
        for (const SendCoinsRecipient &rcp : recipients)
        {
#ifdef ENABLE_BIP70
            if (rcp.paymentRequest.IsInitialized())
            {
                // Make sure any payment requests involved are still valid.
                if (PaymentServer::verifyExpired(rcp.paymentRequest.getDetails())) {
                    return PaymentRequestExpired;
                }

                // Store PaymentRequests in wtx.vOrderForm in wallet.
                std::string value;
                rcp.paymentRequest.SerializeToString(&value);
                vOrderForm.emplace_back("PaymentRequest", std::move(value));
            }
            else
#endif
            if (!rcp.message.isEmpty()) // Message from normal bitcoin:URI (bitcoin:123...?message=example)
                vOrderForm.emplace_back("Message", rcp.message.toStdString());
        }

        auto& newTx = transaction.getWtx();
        std::string rejectReason;
        if (!newTx->commit({} /* mapValue */, std::move(vOrderForm), rejectReason, (recipients[0].useSwiftTX) ? NetMsgType::TXLOCKREQUEST : NetMsgType::TX))
            return SendCoinsReturn(TransactionCommitFailed, QString::fromStdString(rejectReason));

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << newTx->get();
        transaction_array.append(&(ssTx[0]), ssTx.size());
    }

    // Add addresses / update labels that we've sent to the address book,
    // and emit coinsSent signal for each recipient
    for (const SendCoinsRecipient &rcp : transaction.getRecipients())
    {
        // Don't touch the address book when we have a payment request
#ifdef ENABLE_BIP70
        if (!rcp.paymentRequest.IsInitialized())
#endif
        {
            std::string strAddress = rcp.address.toStdString();
            CTxDestination dest = DecodeDestination(strAddress);
            std::string strLabel = rcp.label.toStdString();
            {
                // Check if we have a new address or an updated label
                std::string name;
                if (!m_wallet->getAddress(
                     dest, &name, /* is_mine= */ nullptr, /* purpose= */ nullptr))
                {
                    m_wallet->setAddressBook(dest, strLabel, "send");
                }
                else if (name != strLabel)
                {
                    m_wallet->setAddressBook(dest, strLabel, ""); // "" means don't change purpose
                }
            }
        }
        Q_EMIT coinsSent(this, rcp, transaction_array);
    }

    checkBalanceChanged(m_wallet->getBalances()); // update balance immediately, otherwise there could be a short noticeable delay until pollBalanceChanged hits

    return SendCoinsReturn(OK);
}

//WalletModel::SendCoinsReturn WalletModel::sendCoins(WalletModelTransaction& transaction)
//{
//    QByteArray transaction_array; /* store serialized transaction */
//
//    if (isAnonymizeOnlyUnlocked()) {
//        return AnonymizeOnlyUnlocked;
//    }
//
//    {
//        LOCK2(cs_main, m_wallet->cs_wallet);
//        CWalletTx* newTx = transaction.getTransaction();
//        QList<SendCoinsRecipient> recipients = transaction.getRecipients();
//
//        // Store PaymentRequests in wtx.vOrderForm in wallet.
//        for (const SendCoinsRecipient& rcp: recipients) {
//            if (rcp.paymentRequest.IsInitialized()) {
//                std::string key("PaymentRequest");
//                std::string value;
//                rcp.paymentRequest.SerializeToString(&value);
//                newTx->vOrderForm.push_back(std::make_pair(key, value));
//            } else if (!rcp.message.isEmpty()) // Message from normal wispr:URI (wispr:XyZ...?message=example)
//            {
//                newTx->vOrderForm.push_back(std::make_pair("Message", rcp.message.toStdString()));
//            }
//        }
//
//        CReserveKey* keyChange = transaction.getPossibleKeyChange();
//
//        transaction.getRecipients();
//
//        if (!wallet->CommitTransaction(*newTx, *keyChange, (recipients[0].useSwiftTX) ? NetMsgType::TXLOCKREQUEST : NetMsgType::TX))
//            return TransactionCommitFailed;
//
//        CTransaction* t = (CTransaction*)newTx;
//        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
//        ssTx << *t;
//        transaction_array.append(&(ssTx[0]), ssTx.size());
//    }
//
//    // Add addresses / update labels that we've sent to to the address book,
//    // and emit coinsSent signal for each recipient
//    for (const SendCoinsRecipient& rcp: transaction.getRecipients()) {
//        // Don't touch the address book when we have a payment request
//        if (!rcp.paymentRequest.IsInitialized()) {
//
//            std::string strAddress = rcp.address.toStdString();
//            CTxDestination dest = CBitcoinAddress(strAddress).Get();
//            std::string strLabel = rcp.label.toStdString();
//
//            updateAddressBookLabels(dest, strLabel, "send");
//        }
//        Q_EMIT coinsSent(wallet, rcp, transaction_array);
//    }
//    checkBalanceChanged(); // update balance immediately, otherwise there could be a short noticeable delay until pollBalanceChanged hits
//
//    return SendCoinsReturn(OK);
//}

OptionsModel *WalletModel::getOptionsModel()
{
    return optionsModel;
}

AddressTableModel *WalletModel::getAddressTableModel()
{
    return addressTableModel;
}

TransactionTableModel *WalletModel::getTransactionTableModel()
{
    return transactionTableModel;
}

RecentRequestsTableModel *WalletModel::getRecentRequestsTableModel()
{
    return recentRequestsTableModel;
}

WalletModel::EncryptionStatus WalletModel::getEncryptionStatus() const
{
    if(!m_wallet->isCrypted())
    {
        return Unencrypted;
    }
    else if (m_wallet->isAnonymizeOnlyUnlocked())
    {
        return UnlockedForAnonymizationOnly;
    }
    else if(m_wallet->isLocked())
    {
        return Locked;
    }
    else
    {
        return Unlocked;
    }
}

bool WalletModel::setWalletEncrypted(bool encrypted, const SecureString &passphrase)
{
    if(encrypted)
    {
        // Encrypt
        return m_wallet->encryptWallet(passphrase);
    }
    else
    {
        // Decrypt -- TODO; not supported yet
        return false;
    }
}

bool WalletModel::setWalletLocked(bool locked, const SecureString& passPhrase, bool anonymizeOnly)
{
    if(locked)
    {
        // Lock
        m_wallet->setAnonymizeOnlyUnlocked(false);
        return m_wallet->lock();
    }
    else
    {
        // Unlock
        return m_wallet->unlock(passPhrase, anonymizeOnly);
    }
}

bool WalletModel::isAnonymizeOnlyUnlocked()
{
    return m_wallet->isAnonymizeOnlyUnlocked();
}

bool WalletModel::changePassphrase(const SecureString &oldPass, const SecureString &newPass)
{
    m_wallet->lock(); // Make sure wallet is locked before attempting pass change
    return m_wallet->changeWalletPassphrase(oldPass, newPass);
}

bool WalletModel::backupWallet(const QString& filename)
{
    //attempt regular backup
    if(!m_wallet->backupWallet(filename.toLocal8Bit().data())) {
        return error("ERROR: Failed to backup wallet!");
    }

    return true;
}


// Handlers for core signals
static void NotifyUnload(WalletModel* walletModel)
{
    qDebug() << "NotifyUnload";
    QMetaObject::invokeMethod(walletModel, "unload");
}

static void NotifyKeyStoreStatusChanged(WalletModel *walletmodel)
{
    qDebug() << "NotifyKeyStoreStatusChanged";
    QMetaObject::invokeMethod(walletmodel, "updateStatus", Qt::QueuedConnection);
}

static void NotifyAddressBookChanged(WalletModel *walletmodel,
        const CTxDestination &address, const std::string &label, bool isMine,
        const std::string &purpose, ChangeType status)
{
    QString strAddress = QString::fromStdString(EncodeDestination(address));
    QString strLabel = QString::fromStdString(label);
    QString strPurpose = QString::fromStdString(purpose);

    qDebug() << "NotifyAddressBookChanged: " + strAddress + " " + strLabel + " isMine=" + QString::number(isMine) + " purpose=" + strPurpose + " status=" + QString::number(status);
    QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
                              Q_ARG(QString, strAddress),
                              Q_ARG(QString, strLabel),
                              Q_ARG(bool, isMine),
                              Q_ARG(QString, strPurpose),
                              Q_ARG(int, status));
}

static void NotifyTransactionChanged(WalletModel *walletmodel, const uint256 &hash, ChangeType status)
{
    Q_UNUSED(hash);
    Q_UNUSED(status);
    QMetaObject::invokeMethod(walletmodel, "updateTransaction", Qt::QueuedConnection);
}

static void ShowProgress(WalletModel *walletmodel, const std::string &title, int nProgress)
{
    // emits signal "showProgress"
    QMetaObject::invokeMethod(walletmodel, "showProgress", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(title)),
                              Q_ARG(int, nProgress));
}

static void NotifyWatchonlyChanged(WalletModel *walletmodel, bool fHaveWatchonly)
{
    QMetaObject::invokeMethod(walletmodel, "updateWatchOnlyFlag", Qt::QueuedConnection,
                              Q_ARG(bool, fHaveWatchonly));
}

static void NotifyCanGetAddressesChanged(WalletModel* walletmodel)
{
    QMetaObject::invokeMethod(walletmodel, "canGetAddressesChanged");
}

static void NotifyMultiSigChanged(WalletModel* walletmodel, bool fHaveMultiSig)
{
    QMetaObject::invokeMethod(walletmodel, "updateMultiSigFlag", Qt::QueuedConnection,
                              Q_ARG(bool, fHaveMultiSig));
}

static void NotifyZerocoinChanged(WalletModel* walletmodel, const std::string& hexString,
                                  const std::string& isUsed, ChangeType status)
{
    QString HexStr = QString::fromStdString(hexString);
    QString isUsedStr = QString::fromStdString(isUsed);
    qDebug() << "NotifyZerocoinChanged : " + HexStr + " " + isUsedStr + " status= " + QString::number(status);
    QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
                              Q_ARG(QString, HexStr),
                              Q_ARG(QString, isUsedStr),
                              Q_ARG(int, status));
}

static void NotifyzWSPReset(WalletModel* walletmodel)
{
    qDebug() << "NotifyzWSPReset";
    QMetaObject::invokeMethod(walletmodel, "checkBalanceChanged", Qt::QueuedConnection);
}

static void NotifyWalletBacked(WalletModel* model, const bool& fSuccess, const std::string& filename)
{
    std::string message;
    std::string title = "Backup ";
    CClientUIInterface::MessageBoxFlags method;

    if (fSuccess) {
        message = "The wallet data was successfully saved to ";
        title += "Successful: ";
        method = CClientUIInterface::MessageBoxFlags::MSG_INFORMATION;
    } else {
        message = "There was an error trying to save the wallet data to ";
        title += "Failed: ";
        method = CClientUIInterface::MessageBoxFlags::MSG_ERROR;
    }

    message += _(filename.data());

    QMetaObject::invokeMethod(model, "message", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(title)),
                              Q_ARG(QString, QString::fromStdString(message)),
                              Q_ARG(unsigned int, (unsigned int)method));
}

void WalletModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    m_handler_unload = m_wallet->handleUnload(std::bind(&NotifyUnload, this));
    m_handler_status_changed = m_wallet->handleStatusChanged(std::bind(&NotifyKeyStoreStatusChanged, this));
    m_handler_address_book_changed = m_wallet->handleAddressBookChanged(std::bind(NotifyAddressBookChanged, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
    m_handler_transaction_changed = m_wallet->handleTransactionChanged(std::bind(NotifyTransactionChanged, this, std::placeholders::_1, std::placeholders::_2));
    m_handler_show_progress = m_wallet->handleShowProgress(std::bind(ShowProgress, this, std::placeholders::_1, std::placeholders::_2));
    m_handler_watch_only_changed = m_wallet->handleWatchOnlyChanged(std::bind(NotifyWatchonlyChanged, this, std::placeholders::_1));
    m_handler_can_get_addrs_changed = m_wallet->handleCanGetAddressesChanged(boost::bind(NotifyCanGetAddressesChanged, this));

    m_handler_wallet_backed = m_wallet->handleWalletBacked(std::bind(NotifyWalletBacked, this, std::placeholders::_1, std::placeholders::_2));
    m_handler_multi_sig_changed = m_wallet->handleMultiSigChanged(std::bind(NotifyMultiSigChanged, this, std::placeholders::_1));
    m_handler_zerocoin_changed = m_wallet->handleZerocoinChanged(std::bind(NotifyZerocoinChanged, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    m_handler_zwsp_reset = m_wallet->handleZWspResetChanged(std::bind(NotifyzWSPReset, this));
}

void WalletModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    m_handler_unload->disconnect();
    m_handler_status_changed->disconnect();
    m_handler_address_book_changed->disconnect();
    m_handler_transaction_changed->disconnect();
    m_handler_show_progress->disconnect();
    m_handler_watch_only_changed->disconnect();
    m_handler_can_get_addrs_changed->disconnect();

    m_handler_wallet_backed->disconnect();
    m_handler_multi_sig_changed->disconnect();
    m_handler_zerocoin_changed->disconnect();
    m_handler_zwsp_reset->disconnect();
}

// WalletModel::UnlockContext implementation
WalletModel::UnlockContext WalletModel::requestUnlock(AskPassphraseDialog::Context context, bool relock)
{
    bool was_locked = getEncryptionStatus() == Locked;

    if (!was_locked && isAnonymizeOnlyUnlocked()) {
        setWalletLocked(was_locked);
        m_wallet->setAnonymizeOnlyUnlocked(false);
        was_locked = getEncryptionStatus() == Locked;
    }

    if (was_locked) {
        // Request UI to unlock wallet
        Q_EMIT requireUnlock(context);
    }
    // If wallet is still locked, unlock was failed or cancelled, mark context as invalid
    bool valid = getEncryptionStatus() != Locked;

    return UnlockContext(this, valid, was_locked);
}

WalletModel::UnlockContext::UnlockContext(WalletModel *_wallet, bool _valid, bool _relock):
        wallet(_wallet),
        valid(_valid),
        relock(_relock)
{
}

WalletModel::UnlockContext::~UnlockContext()
{
    if(valid && relock)
    {
        wallet->setWalletLocked(true);
    }
}

void WalletModel::UnlockContext::CopyFrom(const UnlockContext& rhs)
{
    // Transfer context; old object no longer relocks wallet
    *this = rhs;
    rhs.relock = false;
}

bool WalletModel::getPubKey(const CKeyID& address, CPubKey& vchPubKeyOut) const
{
    return wallet().getPubKey(address, vchPubKeyOut);
}


bool WalletModel::isLockedCoin(COutPoint& output) const
{
    return m_wallet->isLockedCoin(output);
}

void WalletModel::lockCoin(COutPoint& output)
{
    m_wallet->lockCoin(output);
}

void WalletModel::unlockCoin(COutPoint& output)
{
    m_wallet->unlockCoin(output);
}

void WalletModel::listLockedCoins(std::vector<COutPoint>& vOutpts)
{
    m_wallet->listLockedCoins(vOutpts);
}


void WalletModel::listZerocoinMints(std::set<CMintMeta>& setMints, bool fUnusedOnly, bool fMaturedOnly, bool fUpdateStatus, bool fWrongSeed)
{
    setMints.clear();
    setMints = m_wallet->listMints(fUnusedOnly, fMaturedOnly, fUpdateStatus, fWrongSeed);
}

void WalletModel::loadReceiveRequests(std::vector<std::string>& vReceiveRequests)
{
    vReceiveRequests = m_wallet->getDestValues("rr"); // receive request
}

bool WalletModel::saveReceiveRequest(const std::string &sAddress, const int64_t nId, const std::string &sRequest)
{
    CTxDestination dest = DecodeDestination(sAddress);

    std::stringstream ss;
    ss << nId;
    std::string key = "rr" + ss.str(); // "rr" prefix = "receive request" in destdata

    if (sRequest.empty())
        return m_wallet->eraseDestData(dest, key);
    else
        return m_wallet->addDestData(dest, key, sRequest);
}

bool WalletModel::bumpFee(uint256 hash, uint256& new_hash)
{
    CCoinControl coin_control;
    coin_control.m_signal_bip125_rbf = true;
    std::vector<std::string> errors;
    CAmount old_fee;
    CAmount new_fee;
    CMutableTransaction mtx;
    if (!m_wallet->createBumpTransaction(hash, coin_control, 0 /* totalFee */, errors, old_fee, new_fee, mtx)) {
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Increasing transaction fee failed") + "<br />(" +
            (errors.size() ? QString::fromStdString(errors[0]) : "") +")");
         return false;
    }

    // allow a user based fee verification
    QString questionString = tr("Do you want to increase the fee?");
    questionString.append("<br />");
    questionString.append("<table style=\"text-align: left;\">");
    questionString.append("<tr><td>");
    questionString.append(tr("Current fee:"));
    questionString.append("</td><td>");
    questionString.append(BitcoinUnits::formatHtmlWithUnit(getOptionsModel()->getDisplayUnit(), old_fee));
    questionString.append("</td></tr><tr><td>");
    questionString.append(tr("Increase:"));
    questionString.append("</td><td>");
    questionString.append(BitcoinUnits::formatHtmlWithUnit(getOptionsModel()->getDisplayUnit(), new_fee - old_fee));
    questionString.append("</td></tr><tr><td>");
    questionString.append(tr("New fee:"));
    questionString.append("</td><td>");
    questionString.append(BitcoinUnits::formatHtmlWithUnit(getOptionsModel()->getDisplayUnit(), new_fee));
    questionString.append("</td></tr></table>");
    SendConfirmationDialog confirmationDialog(tr("Confirm fee bump"), questionString);
    confirmationDialog.exec();
    QMessageBox::StandardButton retval = static_cast<QMessageBox::StandardButton>(confirmationDialog.result());

    // cancel sign&broadcast if user doesn't want to bump the fee
    if (retval != QMessageBox::Yes) {
        return false;
    }

    WalletModel::UnlockContext ctx(requestUnlock(AskPassphraseDialog::Context::Unlock_Full));
    if(!ctx.isValid())
    {
        return false;
    }

    // sign bumped transaction
    if (!m_wallet->signBumpTransaction(mtx)) {
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Can't sign transaction."));
        return false;
    }
    // commit the bumped transaction
    if(!m_wallet->commitBumpTransaction(hash, std::move(mtx), errors, new_hash)) {
        QMessageBox::critical(nullptr, tr("Fee bump error"), tr("Could not commit transaction") + "<br />(" +
            QString::fromStdString(errors[0])+")");
         return false;
    }
    return true;
}

bool WalletModel::isWalletEnabled()
{
   return !gArgs.GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET);
}

bool WalletModel::privateKeysDisabled() const
{
    return m_wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
}

bool WalletModel::canGetAddresses() const
{
    return m_wallet->canGetAddresses();
}

QString WalletModel::getWalletName() const
{
    return QString::fromStdString(m_wallet->getWalletName());
}

QString WalletModel::getDisplayName() const
{
    const QString name = getWalletName();
    return name.isEmpty() ? "["+tr("default wallet")+"]" : name;
}

bool WalletModel::isMultiwallet()
{
    return m_node.getWallets().size() > 1;
}

bool WalletModel::isMine(const std::string &sAddress)
{
    return m_wallet->addressIsMine(sAddress);
}

bool WalletModel::isUsed(const std::string &sAddress)
{
    return m_wallet->addressIsUsed(sAddress);
}
