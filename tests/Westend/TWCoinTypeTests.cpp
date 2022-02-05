// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.
//
// This is a GENERATED FILE, changes made here MAY BE LOST.
// Generated one-time (codegen/bin/cointests)
//

#include "../interface/TWTestUtilities.h"
#include <TrustWalletCore/TWCoinTypeConfiguration.h>
#include <gtest/gtest.h>


TEST(TWWestendCoinType, TWCoinType) {
    auto symbol = WRAPS(TWCoinTypeConfigurationGetSymbol(TWCoinTypeWestend));
    auto txId = WRAPS(TWStringCreateWithUTF8Bytes("0x049312ed3abafa47077a1acedd134fabca3342aada210049ad975a8aa2cb1c4a"));
    auto txUrl = WRAPS(TWCoinTypeConfigurationGetTransactionURL(TWCoinTypeWestend, txId.get()));
    auto accId = WRAPS(TWStringCreateWithUTF8Bytes("5HcWQ2T23JTmY2f9c7T72FJxAtiWyVgsbMyb5VFPzT5H7ch4"));
    auto accUrl = WRAPS(TWCoinTypeConfigurationGetAccountURL(TWCoinTypeWestend, accId.get()));
    auto id = WRAPS(TWCoinTypeConfigurationGetID(TWCoinTypeWestend));
    auto name = WRAPS(TWCoinTypeConfigurationGetName(TWCoinTypeWestend));

    ASSERT_EQ(TWCoinTypeConfigurationGetDecimals(TWCoinTypeWestend), 12);
    ASSERT_EQ(TWBlockchainPolkadot, TWCoinTypeBlockchain(TWCoinTypeWestend));
    ASSERT_EQ(0x0, TWCoinTypeP2shPrefix(TWCoinTypeWestend));
    ASSERT_EQ(0x0, TWCoinTypeStaticPrefix(TWCoinTypeWestend));
    assertStringsEqual(symbol, "WND");
    assertStringsEqual(txUrl, "https://westend.subscan.io/extrinsic/0x049312ed3abafa47077a1acedd134fabca3342aada210049ad975a8aa2cb1c4a");
    assertStringsEqual(accUrl, "https://westend.subscan.io/account/5HcWQ2T23JTmY2f9c7T72FJxAtiWyVgsbMyb5VFPzT5H7ch4");
    assertStringsEqual(id, "Westend");
    assertStringsEqual(name, "Westend");
}
