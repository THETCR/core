// Copyright (c) 2014-2016 The Dash Developers
// Copyright (c) 2016-2017 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OBFUSCATIONCONFIG_H
#define OBFUSCATIONCONFIG_H

#include <QDialog>

namespace Ui
{
class ObfuscationConfig;
}
class WalletModel;

/** Multifunctional dialog to ask for passphrases. Used for encryption, unlocking, and changing the passphrase.
 */
class ObfuscationConfig : public QDialog
{
    Q_OBJECT

public:
    ObfuscationConfig(QWidget* parent = nullptr);
    ~ObfuscationConfig();

    void setModel(WalletModel* model);


private:
    Ui::ObfuscationConfig* ui;
    WalletModel* model;
    void configure(bool enabled, int coins, int rounds);

private Q_SLOTS:

    void clickBasic();
    void clickHigh();
    void clickMax();
};

#endif // OBFUSCATIONCONFIG_H
