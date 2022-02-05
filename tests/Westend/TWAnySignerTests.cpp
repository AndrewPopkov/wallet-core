//// Copyright © 2017-2020 Trust Wallet.
////
//// This file is part of Trust. The full Trust copyright notice, including
//// terms governing use, modification, and redistribution, is contained in the
//// file LICENSE at the root of the source code distribution tree.
//
#include "HexCoding.h"
#include "proto/Polkadot.pb.h"
#include "uint256.h"
#include "../interface/TWTestUtilities.h"
#include <TrustWalletCore/TWAnySigner.h>

#include <gtest/gtest.h>

using namespace TW;
using namespace TW::Polkadot;
//
TEST(TWAnySignerWestend, Sign) {
    auto key = parse_hex("0x34a1d0dda182d758b849223b0f082205c2a4d2186357cfb292f96935086c1d42");
    auto genesisHash = parse_hex("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e");

    Proto::SigningInput input;
    input.set_block_hash(genesisHash.data(), genesisHash.size());
    input.set_genesis_hash(genesisHash.data(), genesisHash.size());
    input.set_nonce(1);
    input.set_spec_version(2019);
    input.set_private_key(key.data(), key.size());
    input.set_network(Proto::Network::WESTEND);
    input.set_transaction_version(2);

    auto balanceCall = input.mutable_balance_call();
    auto& transfer = *balanceCall->mutable_transfer();
    auto value = store(uint256_t(10000000000));
    transfer.set_to_address("5C8ssaTbSTxDtTRf97rJ8cDrLzeQDULHHEnq4ngjjRMMoQRw");
    transfer.set_value(value.data(), value.size());

    Proto::SigningOutput output;
    ANY_SIGN(input, TWCoinTypeWestend);

    ASSERT_EQ(hex(output.encoded()), "3d028400f56e71ce6281e50a0c8f57d8517c15f5e1cbf9b09d6ee19989ee5d84680e48e50030b916db40600997b581023a40ef2c00b81aa401b313be048d957a737cefa777e3b8b5c0a0a0440845b8bd3962d74c1a77a06be2aaff14a877df2853cba83202000400040000032eb287017c5cde2940b5dd062d413f9d09f8aa44723fc80bf46b96c81ac23d0700e40b5402");
}
