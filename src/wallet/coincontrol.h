// Copyright (c) 2011-2013 The Bitcoin developers
// Copyright (c) 2014-2016 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COINCONTROL_H
#define BITCOIN_COINCONTROL_H

#include <policy/feerate.h>
#include <policy/fees.h>
#include <primitives/transaction.h>
#include <wallet/wallet.h>
#include <boost/optional.hpp>

/** Coin Control Features. */
class CCoinControl
{
public:
    CTxDestination destChange;
    bool useObfuScation;
    bool useSwiftTX;
    bool fSplitBlock;
    int nSplitBlock;
    //! Minimum absolute fee (not per kilobyte)
    CAmount nMinimumTotalFee;
  //! Override the default change type if set, ignored if destChange is set
//  boost::optional<OutputType> m_change_type;
  //! If false, allows unselected inputs, but requires all selected inputs be used
  bool fAllowOtherInputs;
  //! Includes watch only addresses which are solvable
  bool fAllowWatchOnly;
  //! Override automatic min/max checks on fee, m_feerate must be set if true
  bool fOverrideFeeRate;
  //! Override the wallet's m_pay_tx_fee if set
  boost::optional<CFeeRate> m_feerate;
  //! Override the default confirmation target if set
  boost::optional<unsigned int> m_confirm_target;
  //! Override the wallet's m_signal_rbf if set
  boost::optional<bool> m_signal_bip125_rbf;
  //! Avoid partial use of funds sent to a given address
  bool m_avoid_partial_spends;
  //! Fee estimation mode to control arguments to estimateSmartFee
//  FeeEstimateMode m_fee_mode;

  CCoinControl()
  {
      SetNull();
  }

    void SetNull();

    bool HasSelected() const
    {
        return (setSelected.size() > 0);
    }

    bool IsSelected(const uint256& hash, unsigned int n) const
    {
        COutPoint outpt(hash, n);
        return (setSelected.count(outpt) > 0);
    }

    void Select(const COutPoint& output)
    {
        setSelected.insert(output);
    }

    void UnSelect(const COutPoint& output)
    {
        setSelected.erase(output);
    }

    void UnSelectAll()
    {
        setSelected.clear();
    }

    void ListSelected(std::vector<COutPoint>& vOutpoints)
    {
        vOutpoints.assign(setSelected.begin(), setSelected.end());
    }

    unsigned int QuantitySelected()
    {
        return setSelected.size();
    }

    void SetSelection(std::set<COutPoint> setSelected)
    {
        this->setSelected.clear();
        this->setSelected = setSelected;
    }

private:
    std::set<COutPoint> setSelected;
};

#endif // BITCOIN_COINCONTROL_H
