// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Polkadot/Signer.h"
#include "Polkadot/Extrinsic.h"
#include "SS58Address.h"
#include "HexCoding.h"
#include "PrivateKey.h"
#include "PublicKey.h"
#include "proto/Polkadot.pb.h"
#include "uint256.h"

#include <TrustWalletCore/TWSS58AddressType.h>
#include <gtest/gtest.h>


namespace TW::Polkadot {
    extern PrivateKey privateKey;
    extern PublicKey toPublicKey;
    auto genesisHashWND = parse_hex("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e");

TEST(PolkadotSigner, SignTransferWND) {
    auto blockHash = parse_hex("024d2f8333ce893eef1cf740b37826de58f4f7c70117e18f5725c4ce87836d8e");
    auto toAddress = SS58Address(toPublicKey, TWSS58AddressTypeWestend);

    auto input = Proto::SigningInput();
    input.set_block_hash(blockHash.data(), blockHash.size());
    input.set_genesis_hash(genesisHashWND.data(), genesisHashWND.size());
    input.set_nonce(0);
    input.set_spec_version(2019);
    input.set_private_key(privateKey.bytes.data(), privateKey.bytes.size());
    input.set_network(Proto::Network::WESTEND);
    input.set_transaction_version(2);

    auto balanceCall = input.mutable_balance_call();
    auto& transfer = *balanceCall->mutable_transfer();
    auto value = store(uint256_t(12345));
    transfer.set_to_address(toAddress.string());
    transfer.set_value(value.data(), value.size());

    auto extrinsic = Extrinsic(input);
    auto preimage = extrinsic.encodePayload();
    auto output = Signer::sign(input);

    ASSERT_EQ(hex(preimage), "0400008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48e5c0000000e307000002000000e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e024d2f8333ce893eef1cf740b37826de58f4f7c70117e18f5725c4ce87836d8e");
    ASSERT_EQ(hex(output.encoded()), "2d02840088dc3417d5058ec4b4503e0c12ea1a0a89be200fe98922423d4334014fa6b0ee00d9447e99f4543aeb300f7dac1fcb3c30d3feef4a7e285905fdf4a070d195036e6d48c24cb47e275940608904432c1cc453ea00628ec3e271d1fab98d6e4026040000000400008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48e5c0");
}

} // namespace
