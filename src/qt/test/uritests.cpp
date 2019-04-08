// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2017 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/uritests.h>

#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <QUrl>

void URITests::uriTests()
{
    SendCoinsRecipient rv;
    QUrl uri;
    uri.setUrl(QString("wispr:Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N?req-dontexist="));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("wispr:Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N?dontexist="));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("wispr:Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N?label=Some Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N"));
    QVERIFY(rv.label == QString("Some Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("wispr:Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N?amount=0.001"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100000);

    uri.setUrl(QString("wispr:Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N?amount=1.001"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 100100000);

    uri.setUrl(QString("wispr:Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N?amount=100&label=Some Example"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N"));
    QVERIFY(rv.amount == 10000000000LL);
    QVERIFY(rv.label == QString("Some Example"));

    uri.setUrl(QString("wispr:Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N?message=Some Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N"));
    QVERIFY(rv.label == QString());

    QVERIFY(GUIUtil::parseBitcoinURI("wispr://Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N?message=Some Example Address", &rv));
    QVERIFY(rv.address == QString("Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString("wispr:Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N?req-message=Some Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("wispr:Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N?amount=1,000&label=Some Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("wispr:Wa4qRD6Eg9zZAUGA9NYgRDVeW3VEXC1x3N?amount=1,000.0&label=Some Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));
}
