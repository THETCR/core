WISPR Core version *3.3.0* is now available from:  <https://github.com/WisprProject/core/releases>

This is a new major version release, including various bug fixes and performance improvements, as well as updated translations.

Please report bugs using the issue tracker at github: <https://github.com/WisprProject/core/issues>


Mandatory Update
==============

WISPR Core v3.3.0 is a mandatory update for all users. This release contains new consensus rules and improvements that are not backwards compatible with older versions. Users will have a grace period of approximately one week to update their clients before enforcement of this update goes into effect.

Masternodes will need to be restarted once both the masternode daemon and the controller wallet have been upgraded.

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely shut down (which might take a few minutes for older versions), then run the installer (on Windows) or just copy over /Applications/WISPR-Qt (on Mac) or wisprd/wispr-qt (on Linux).


Compatibility
==============

WISPR Core is extensively tested on multiple operating systems using the Linux kernel, macOS 10.10+, and Windows 7 and later.

Microsoft ended support for Windows XP on [April 8th, 2014](https://www.microsoft.com/en-us/WindowsForBusiness/end-of-xp-support), No attempt is made to prevent installing or running the software on Windows XP, you can still do so at your own risk but be aware that there are known instabilities and issues. Please do not report issues about Windows XP to the issue tracker.

Apple released it's last Mountain Lion update August 13, 2015, and officially ended support on [December 14, 2015](http://news.fnal.gov/2015/10/mac-os-x-mountain-lion-10-8-end-of-life-december-14/). WISPR Core software starting with v3.2.0 will no longer run on MacOS versions prior to Yosemite (10.10). Please do not report issues about MacOS versions prior to Yosemite to the issue tracker.

WISPR Core should also work on most other Unix-like systems but is not frequently tested on them.


Notable Changes
==============

(Developers: add your notes here as part of your pull requests whenever possible)

*3.3.0* Change log
==============

Detailed release notes follow. This overview includes changes that affect behavior, not code moves, refactors and string updates. For convenience in locating the code changes and accompanying discussion, both the pull request and git merge commit are mentioned.

### Core
 - #875 `a99c2dd3bb` [Zerocoin] GMP BigNum: Fix limits for random number generators (random-zebra)
 - #888 `0c071c3fd0` [Zerocoin] remove CTransaction::IsZerocoinSpend/IsZerocoinMint (random-zebra)
 - #891 `855408c2c3` [ZWSP] Zerocoin public coin spend. (furszy)
 - #897 `65bd788945` [zWSP] Disable zerocoin minting (random-zebra)
 - #899 `4b22a09024` [zWSP] Disable zWSP staking (random-zebra)
 - #909 `458b08c8f2` [Consensus] Mainnet public spend enforcement height set. (furszy)
 - #924 `988b33dab8` [Backport] Max tip age to consider a node in IBD status customizable. (furszy)
 - #925 `a9827a0e63` [Consensus] Time checks (warrows)

### Build System

### P2P Protocol and Network Code
 - #908 `95b584effd` [NET] Non-running dns servers removed from chainParams. (furszy)
 - #929 `7e8855d910` [Net] Update hard-coded seeds (Fuzzbawls)
 - #930 `5061b486c2` [Net] Add a couple new testnet checkpoints (Fuzzbawls)

### GUI

### RPC/REST
 - #877 `54c8832d80` [RPC] Remove deprecated masternode/budget RPC commands (Fuzzbawls)
 - #901 `be3aab4a00` [RPC] Fix typos and oversights in listunspent (CaveSpectre11)
 - #911 `484c070b22` [RPC] add 'getblockindexstats' function (random-zebra)

### Wallet

### Miscellaneous


## Credits

Thanks to everyone who directly contributed to this release:

 - Alko89
 - CaveSpectre11
 - Fuzzbawls
 - Julian Meyer
 - Matias Furszyfer
 - cevap
 - Wladimir J. van der Laan
 - random-zebra
 - warrows

As well as everyone that helped translating on [Transifex](https://www.transifex.com/projects/p/wispr-project-translations/), the QA team during Testing and the Node hosts supporting our Testnet.
