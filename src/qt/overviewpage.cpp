// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/overviewpage.h>
#include <qt/forms/ui_overviewpage.h>

#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include "obfuscation.h"
#include "obfuscationconfig.h"
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/transactionfilterproxy.h>
#include "transactionrecord.h"
#include <qt/transactiontablemodel.h>
#include <qt/walletmodel.h>

#include <QAbstractItemDelegate>
#include <QPainter>
#include <QPushButton>
#include <QSettings>
#include <QTimer>

#define DECORATION_SIZE 48
#define ICON_OFFSET 16
#define NUM_ITEMS 9

Q_DECLARE_METATYPE(interfaces::WalletBalances)

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    explicit TxViewDelegate(const PlatformStyle *_platformStyle, QObject *parent=nullptr):
        QAbstractItemDelegate(parent), unit(BitcoinUnits::WSP),
        platformStyle(_platformStyle)
    {

    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(Qt::DecorationRole));
        QRect mainRect = option.rect;
        mainRect.moveLeft(ICON_OFFSET);
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2 * ypad) / 2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top() + ypad, mainRect.width() - xspace - ICON_OFFSET, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top() + ypad + halfheight, mainRect.width() - xspace, halfheight);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = COLOR_BLACK;
        if (value.canConvert<QBrush>()) {
            QBrush brush = qvariant_cast<QBrush>(value);
            foreground = brush.color();
        }

        painter->setPen(foreground);
        QRect boundingRect;
        painter->drawText(addressRect, Qt::AlignLeft | Qt::AlignVCenter, address, &boundingRect);

        if (index.data(TransactionTableModel::WatchonlyRole).toBool()) {
            QIcon iconWatchonly = qvariant_cast<QIcon>(index.data(TransactionTableModel::WatchonlyDecorationRole));
            QRect watchonlyRect(boundingRect.right() + 5, mainRect.top() + ypad + halfheight, 16, halfheight);
            iconWatchonly.paint(painter, watchonlyRect);
        }

        if (amount < 0)
            foreground = COLOR_NEGATIVE;

        painter->setPen(foreground);
        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true, BitcoinUnits::separatorAlways);
        if (!confirmed) {
            amountText = QString("[") + amountText + QString("]");
        }
        painter->drawText(amountRect, Qt::AlignRight | Qt::AlignVCenter, amountText);

        painter->setPen(COLOR_BLACK);
        painter->drawText(amountRect, Qt::AlignLeft | Qt::AlignVCenter, GUIUtil::dateTimeStr(date));

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE);
    }

    int unit;
    const PlatformStyle *platformStyle;

};
#include <qt/overviewpage.moc>

OverviewPage::OverviewPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OverviewPage),
    clientModel(nullptr),
    walletModel(nullptr),
    txdelegate(new TxViewDelegate(platformStyle, this))
{
    nDisplayUnit = 0; // just make sure it's not unitialized
    ui->setupUi(this);

    m_balances.balance = -1;

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, &QListView::clicked, this, &OverviewPage::handleTransactionClicked);

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
//    connect(ui->labelWalletStatus, &QPushButton::clicked, this, &OverviewPage::handleOutOfSyncWarningClicks);
//    connect(ui->labelTransactionsStatus, &QPushButton::clicked, this, &OverviewPage::handleOutOfSyncWarningClicks);
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        Q_EMIT transactionClicked(filter->mapToSource(index));
}

void OverviewPage::handleOutOfSyncWarningClicks()
{
    Q_EMIT outOfSyncWarningClicked();
}

OverviewPage::~OverviewPage()
{
    delete ui;
}

void OverviewPage::getPercentage(CAmount nUnlockedBalance, CAmount nZerocoinBalance, QString& sWSPPercentage, QString& szWSPPercentage)
{
    int nPrecision = 2;
    double dzPercentage = 0.0;

    if (nZerocoinBalance <= 0){
        dzPercentage = 0.0;
    }
    else{
        if (nUnlockedBalance <= 0){
            dzPercentage = 100.0;
        }
        else{
            dzPercentage = 100.0 * (double)(nZerocoinBalance / (double)(nZerocoinBalance + nUnlockedBalance));
        }
    }

    double dPercentage = 100.0 - dzPercentage;

    szWSPPercentage = "(" + QLocale(QLocale::system()).toString(dzPercentage, 'f', nPrecision) + " %)";
    sWSPPercentage = "(" + QLocale(QLocale::system()).toString(dPercentage, 'f', nPrecision) + " %)";

}

void OverviewPage::setBalance(const interfaces::WalletBalances& balances)
{
    int unit = walletModel->getOptionsModel()->getDisplayUnit();
    m_balances = balances;
    CAmount balance = balances.balance;
    CAmount unconfirmedBalance = balances.unconfirmed_balance;
    CAmount immatureBalance = balances.immature_balance;
    CAmount zerocoinBalance = balances.zerocoin_balance;
    CAmount unconfirmedZerocoinBalance = balances.unconfirmed_zerocoin_balance;
    CAmount immatureZerocoinBalance = balances.immature_zerocoin_balance;
    CAmount watchOnlyBalance = balances.watch_only_balance;
    CAmount watchUnconfBalance = balances.unconfirmed_watch_only_balance;
    CAmount watchImmatureBalance = balances.immature_watch_only_balance;

    CAmount nLockedBalance = 0;
    CAmount nWatchOnlyLockedBalance = 0;
    if (walletModel) {
        nLockedBalance = walletModel->getLockedBalance();
        nWatchOnlyLockedBalance = walletModel->wallet().getLockedWatchOnlyBalance();
    }

    // WSP Balance
    CAmount nTotalBalance = balance + unconfirmedBalance;
    CAmount wspAvailableBalance = balance - immatureBalance - nLockedBalance;
    CAmount nUnlockedBalance = nTotalBalance - nLockedBalance;

    // WSP Watch-Only Balance
    CAmount nTotalWatchBalance = watchOnlyBalance + watchUnconfBalance;
    CAmount nAvailableWatchBalance = watchOnlyBalance - watchImmatureBalance - nWatchOnlyLockedBalance;

    // zWSP Balance
    CAmount matureZerocoinBalance = zerocoinBalance - unconfirmedZerocoinBalance - immatureZerocoinBalance;

    // Percentages
    QString szPercentage = "";
    QString sPercentage = "";
    getPercentage(nUnlockedBalance, zerocoinBalance, sPercentage, szPercentage);
    // Combined balances
    CAmount availableTotalBalance = wspAvailableBalance + matureZerocoinBalance;
    CAmount sumTotalBalance = nTotalBalance + zerocoinBalance;

    // WSP labels
    ui->labelBalance->setText(BitcoinUnits::formatWithUnit(unit, wspAvailableBalance, false, BitcoinUnits::separatorAlways));
    ui->labelUnconfirmed->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedBalance, false, BitcoinUnits::separatorAlways));
    ui->labelImmature->setText(BitcoinUnits::formatWithUnit(unit, immatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelLockedBalance->setText(BitcoinUnits::formatWithUnit(unit, nLockedBalance, false, BitcoinUnits::separatorAlways));
    ui->labelTotal->setText(BitcoinUnits::formatWithUnit(unit, nTotalBalance, false, BitcoinUnits::separatorAlways));

    // Watchonly labels
    ui->labelWatchAvailable->setText(BitcoinUnits::formatWithUnit(unit, nAvailableWatchBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchPending->setText(BitcoinUnits::formatWithUnit(unit, watchUnconfBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchImmature->setText(BitcoinUnits::formatWithUnit(unit, watchImmatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchLocked->setText(BitcoinUnits::formatWithUnit(unit, nWatchOnlyLockedBalance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchTotal->setText(BitcoinUnits::formatWithUnit(unit, nTotalWatchBalance, false, BitcoinUnits::separatorAlways));

    // zWSP labels
    ui->labelzBalance->setText(BitcoinUnits::formatWithUnit(unit, zerocoinBalance, false, BitcoinUnits::separatorAlways));
    ui->labelzBalanceUnconfirmed->setText(BitcoinUnits::formatWithUnit(unit, unconfirmedZerocoinBalance, false, BitcoinUnits::separatorAlways));
    ui->labelzBalanceMature->setText(BitcoinUnits::formatWithUnit(unit, matureZerocoinBalance, false, BitcoinUnits::separatorAlways));
    ui->labelzBalanceImmature->setText(BitcoinUnits::formatWithUnit(unit, immatureZerocoinBalance, false, BitcoinUnits::separatorAlways));

    // Combined labels
    ui->labelBalancez->setText(BitcoinUnits::formatWithUnit(unit, availableTotalBalance, false, BitcoinUnits::separatorAlways));
    ui->labelTotalz->setText(BitcoinUnits::formatWithUnit(unit, sumTotalBalance, false, BitcoinUnits::separatorAlways));

    // Percentage labels
    ui->labelWSPPercent->setText(sPercentage);
    ui->labelzWSPPercent->setText(szPercentage);

    // Adjust bubble-help according to AutoMint settings
    QString automintHelp = tr("Current percentage of zWSP.\nIf AutoMint is enabled this percentage will settle around the configured AutoMint percentage (default = 10%).\n");
    bool fEnableZeromint = gArgs.GetBoolArg("-enablezeromint", true);
    int nZeromintPercentage = gArgs.GetArg("-zeromintpercentage", 10);
    if (fEnableZeromint) {
        automintHelp += tr("AutoMint is currently enabled and set to ") + QString::number(nZeromintPercentage) + "%.\n";
        automintHelp += tr("To disable AutoMint add 'enablezeromint=0' in wispr.conf.");
    }
    else {
        automintHelp += tr("AutoMint is currently disabled.\nTo enable AutoMint change 'enablezeromint=0' to 'enablezeromint=1' in wispr.conf");
    }

    // Only show most balances if they are non-zero for the sake of simplicity
    QSettings settings;
    bool settingShowAllBalances = !settings.value("fHideZeroBalances").toBool();

    bool showSumAvailable = settingShowAllBalances || sumTotalBalance != availableTotalBalance;
    ui->labelBalanceTextz->setVisible(showSumAvailable);
    ui->labelBalancez->setVisible(showSumAvailable);

    bool showWatchOnly = nTotalWatchBalance != 0;

    // WSP Available
    bool showWSPAvailable = settingShowAllBalances || wspAvailableBalance != nTotalBalance;
    bool showWatchOnlyWSPAvailable = showWSPAvailable || nAvailableWatchBalance != nTotalWatchBalance;
    ui->labelBalanceText->setVisible(showWSPAvailable || showWatchOnlyWSPAvailable);
    ui->labelBalance->setVisible(showWSPAvailable || showWatchOnlyWSPAvailable);
    ui->labelWatchAvailable->setVisible(showWatchOnlyWSPAvailable && showWatchOnly);

    // WSP Pending
    bool showWSPPending = settingShowAllBalances || unconfirmedBalance != 0;
    bool showWatchOnlyWSPPending = showWSPPending || watchUnconfBalance != 0;
    ui->labelPendingText->setVisible(showWSPPending || showWatchOnlyWSPPending);
    ui->labelUnconfirmed->setVisible(showWSPPending || showWatchOnlyWSPPending);
    ui->labelWatchPending->setVisible(showWatchOnlyWSPPending && showWatchOnly);

    // WSP Immature
    bool showWSPImmature = settingShowAllBalances || immatureBalance != 0;
    bool showWatchOnlyImmature = showWSPImmature || watchImmatureBalance != 0;
    ui->labelImmatureText->setVisible(showWSPImmature || showWatchOnlyImmature);
    ui->labelImmature->setVisible(showWSPImmature || showWatchOnlyImmature); // for symmetry reasons also show immature label when the watch-only one is shown
    ui->labelWatchImmature->setVisible(showWatchOnlyImmature && showWatchOnly); // show watch-only immature balance

    // WSP Locked
    bool showWSPLocked = settingShowAllBalances || nLockedBalance != 0;
    bool showWatchOnlyWSPLocked = showWSPLocked || nWatchOnlyLockedBalance != 0;
    ui->labelLockedBalanceText->setVisible(showWSPLocked || showWatchOnlyWSPLocked);
    ui->labelLockedBalance->setVisible(showWSPLocked || showWatchOnlyWSPLocked);
    ui->labelWatchLocked->setVisible(showWatchOnlyWSPLocked && showWatchOnly);

    // zWSP
    bool showzWSPAvailable = settingShowAllBalances || zerocoinBalance != matureZerocoinBalance;
    bool showzWSPUnconfirmed = settingShowAllBalances || unconfirmedZerocoinBalance != 0;
    bool showzWSPImmature = settingShowAllBalances || immatureZerocoinBalance != 0;
    ui->labelzBalanceMature->setVisible(showzWSPAvailable);
    ui->labelzBalanceMatureText->setVisible(showzWSPAvailable);
    ui->labelzBalanceUnconfirmed->setVisible(showzWSPUnconfirmed);
    ui->labelzBalanceUnconfirmedText->setVisible(showzWSPUnconfirmed);
    ui->labelzBalanceImmature->setVisible(showzWSPImmature);
    ui->labelzBalanceImmatureText->setVisible(showzWSPImmature);

    // Percent split
    bool showPercentages = ! (zerocoinBalance == 0 && nTotalBalance == 0);
    ui->labelWSPPercent->setVisible(showPercentages);
    ui->labelzWSPPercent->setVisible(showPercentages);

    static int cachedTxLocks = 0;

    if (cachedTxLocks != nCompleteTXLocks) {
        cachedTxLocks = nCompleteTXLocks;
        ui->listTransactions->update();
    }
}

// show/hide watch-only labels
void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{
    ui->labelSpendable->setVisible(showWatchOnly);      // show spendable label (only when watch-only is active)
    ui->labelWatchonly->setVisible(showWatchOnly);      // show watch-only label
    ui->labelWatchAvailable->setVisible(showWatchOnly); // show watch-only available balance
    ui->labelWatchPending->setVisible(showWatchOnly);   // show watch-only pending balance
    ui->labelWatchLocked->setVisible(showWatchOnly);     // show watch-only total balance
    ui->labelWatchTotal->setVisible(showWatchOnly);     // show watch-only total balance

    if (!showWatchOnly) {
        ui->labelWatchImmature->hide();
    } else {
        ui->labelBalance->setIndent(20);
        ui->labelUnconfirmed->setIndent(20);
        ui->labelLockedBalance->setIndent(20);
        ui->labelImmature->setIndent(20);
        ui->labelTotal->setIndent(20);
    }
}

void OverviewPage::setClientModel(ClientModel* model)
{
    this->clientModel = model;
    if (model) {
        // Show warning if this is a prerelease version
        connect(model, &ClientModel::alertsChanged, this, &OverviewPage::updateAlerts);
        updateAlerts(model->getStatusBarWarnings());
    }
}

void OverviewPage::setWalletModel(WalletModel* model)
{
    this->walletModel = model;
    if (model && model->getOptionsModel()) {
        // Set up transaction list
        filter.reset(new TransactionFilterProxy());
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter.get());
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        // Keep up to date with wallet
        interfaces::Wallet& wallet = model->wallet();
        interfaces::WalletBalances balances = wallet.getBalances();
        setBalance(balances);
        connect(model, &WalletModel::balanceChanged, this, &OverviewPage::setBalance);

        connect(model->getOptionsModel(), &OptionsModel::displayUnitChanged, this, &OverviewPage::updateDisplayUnit);
        connect(model->getOptionsModel(), SIGNAL(hideZeroBalancesChanged(bool)), this, SLOT(updateDisplayUnit()));
        connect(model->getOptionsModel(), SIGNAL(hideOrphansChanged(bool)), this, SLOT(hideOrphans(bool)));

        updateWatchOnlyLabels(wallet.haveWatchOnly() && !model->privateKeysDisabled());
        connect(model, &WalletModel::notifyWatchonlyChanged, [this](bool showWatchOnly) {
            updateWatchOnlyLabels(showWatchOnly && !walletModel->privateKeysDisabled());
        });
    }

    // update the display unit, to not use the default ("WSP")
    updateDisplayUnit();
}

void OverviewPage::updateDisplayUnit()
{
    if(walletModel && walletModel->getOptionsModel())
    {
        if (m_balances.balance != -1) {
            setBalance(m_balances);
        }

        // Update txdelegate->unit with the current unit
        txdelegate->unit = walletModel->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::updateAlerts(const QString &warnings)
{
    this->ui->labelAlerts->setVisible(!warnings.isEmpty());
    this->ui->labelAlerts->setText(warnings);
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    ui->labelWalletStatus->setVisible(fShow);
    ui->labelTransactionsStatus->setVisible(fShow);
}

void OverviewPage::hideOrphans(bool fHide)
{
    if (filter)
        filter->setHideOrphans(fHide);
}
