// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "Polkadot/Extrinsic.h"
#include "Polkadot/Signer.h"
#include "PrivateKey.h"
#include "PublicKey.h"
#include "proto/Polkadot.pb.h"
#include "uint256.h"
#include <TrustWalletCore/TWAnySigner.h>
#include <TrustWalletCore/TWCoinType.h>
#include <TrustWalletCore/TWData.h>
#include <TrustWalletCore/TWString.h>

#include "HexCoding.h"
#include <curl/curl.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
using json = nlohmann::json;

using namespace std;

#define WRAPD(x) std::shared_ptr<TWData>(x, TWDataDelete)

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}
int main() {
    try {

        CURL* curl;
        CURLcode res;

        std::string readBuffer_Head;
        std::string readBuffer_RuntimeVersion;
        std::string readBuffer_GetBlockHash;
        curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
            curl_easy_setopt(curl, CURLOPT_URL, "https://westend-rpc.polkadot.io");
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
            struct curl_slist* headers = NULL;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            const char* data = "{\"id\":1, \"jsonrpc\":\"2.0\", \"method\":\"chain_getHeader\", "
                               "\"params\":[]}";
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer_Head);
            res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);
        }

        curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
            curl_easy_setopt(curl, CURLOPT_URL, "https://westend-rpc.polkadot.io");
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
            struct curl_slist* headers = NULL;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            const char* data = "{\"id\":1, \"jsonrpc\":\"2.0\", "
                               "\"method\":\"chain_getRuntimeVersion\", \"params\":[]}";
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer_RuntimeVersion);
            res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);
        }
        auto responseJson_Head = json::parse(readBuffer_Head);
        curl = curl_easy_init();
        //        cout << responseJson_Head["result"]["number"] << endl;
        std::string block_hex = responseJson_Head["result"]["number"];
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
            curl_easy_setopt(curl, CURLOPT_URL, "https://westend-rpc.polkadot.io");
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
            struct curl_slist* headers = NULL;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            std::string data("{\"id\":1, \"jsonrpc\":\"2.0\", "
                             "\"method\":\"chain_getBlockHash\", \"params\":[\"");
            data += block_hex;
            data += std::string("\"]} ");
            //            cout << data << endl;
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer_GetBlockHash);
            res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);
        }

        auto responseJson_RuntimeVersion = json::parse(readBuffer_RuntimeVersion);
        auto responseJson_GetBlockHash = json::parse(readBuffer_GetBlockHash);

        auto block_num = std::stol(block_hex, nullptr, 16);
        auto specVersion = responseJson_RuntimeVersion["result"]["specVersion"];
        auto transactionVersion = responseJson_RuntimeVersion["result"]["transactionVersion"];
        auto BlockHash = responseJson_GetBlockHash["result"];
        cout << block_num << endl;
        cout << responseJson_GetBlockHash << endl;
        cout << specVersion << endl;
        cout << transactionVersion << endl;

        //        auto key =
        //        TW::parse_hex("0x34a1d0dda182d758b849223b0f082205c2a4d2186357cfb292f96935086c1d42");
        auto genesisHash =
            TW::parse_hex("e143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e");
        auto blockHash = TW::parse_hex(BlockHash);
        auto key = TW::PrivateKey(
            TW::parse_hex("34a1d0dda182d758b849223b0f082205c2a4d2186357cfb292f96935086c1d42"));
        TW::PublicKey publicKey = key.getPublicKey(TWPublicKeyTypeED25519);
        TW::Polkadot::Address address = TW::Polkadot::Address(publicKey);

        TW::Polkadot::Proto::SigningInput input;
        input.set_block_hash(blockHash.data(), blockHash.size());
        input.set_genesis_hash(genesisHash.data(), genesisHash.size());
        input.set_nonce(0);
        input.set_spec_version(specVersion);
        input.set_private_key(key.bytes.data(), key.bytes.size());
        input.set_network(TW::Polkadot::Proto::Network::WESTEND);
        input.set_transaction_version(transactionVersion);

        auto era = input.mutable_era();
        era->set_block_number(block_num);
        era->set_period(8);

        auto balanceCall = input.mutable_balance_call();
        auto transfer = balanceCall->mutable_transfer();
        auto value = TW::store(TW::uint256_t(2000000000)); // 0.002
        transfer->set_to_address("5C8ssaTbSTxDtTRf97rJ8cDrLzeQDULHHEnq4ngjjRMMoQRw");
        transfer->set_value(value.data(), value.size());

        //        auto extrinsic = TW::Polkadot::Extrinsic(input);
        //        auto preimage = TW::hex(extrinsic.encodePayload());
        //        cout << preimage << endl;

        TW::Polkadot::Proto::SigningOutput output;
        auto inputData = input.SerializeAsString();
        auto inputTWData =
            WRAPD(TWDataCreateWithBytes((const uint8_t*)inputData.data(), inputData.size()));
        auto outputTWData = WRAPD(TWAnySignerSign(inputTWData.get(), TWCoinTypeWestend));
        output.ParseFromArray(TWDataBytes(outputTWData.get()),
                              static_cast<int>(TWDataSize(outputTWData.get())));
        //        auto output = TW::Polkadot::Signer::sign(input);
        auto result = TW::hex(output.encoded());
        cout << "0x" << result << endl;
        return 0;

    } catch (const exception& ex) {
        cout << "EXCEPTION: " << ex.what() << endl;
        throw ex;
    }
}
//curl --location --request POST 'https://westend-rpc.polkadot.io' \
//--header 'Content-Type: application/json' \
//--data-raw '{"id":1, "jsonrpc":"2.0", "method": "author_submitExtrinsic",
// "params":["0x3d028400f56e71ce6281e50a0c8f57d8517c15f5e1cbf9b09d6ee19989ee5d84680e48e50090bd
// 9d84cff4692ab6c8fff2928fbd42af94548003b080d357a9a79d65cf74180340b2ba556db8211be1cc23edd8133
// a26aed3e078aa20c2c955da8fb4ea550932000000040000032eb287017c5cde2940b5dd062d413f9d09f8aa44723
// fc80bf46b96c81ac23d0300943577"]}'

//https://westend.subscan.io/extrinsic/0x049312ed3abafa47077a1acedd134fabca3342aada210049ad975a8aa2cb1c4a
