// Copyright (c) 2018 The zPrime developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TRANSACTION_BUILDER_H
#define TRANSACTION_BUILDER_H

#include "coins.h"
#include "consensus/params.h"
#include "keystore.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "uint256.h"
#include "zprime/Address.hpp"
#include "zprime/IncrementalMerkleTree.hpp"
#include "zprime/JoinSplit.hpp"
#include "zprime/Note.hpp"
#include "zprime/NoteEncryption.hpp"

#include <boost/optional.hpp>

struct SpendDescriptionInfo {
    libzprime::SaplingExpandedSpendingKey expsk;
    libzprime::SaplingNote note;
    uint256 alpha;
    uint256 anchor;
    SaplingWitness witness;

    SpendDescriptionInfo(
        libzprime::SaplingExpandedSpendingKey expsk,
        libzprime::SaplingNote note,
        uint256 anchor,
        SaplingWitness witness);
};

struct OutputDescriptionInfo {
    uint256 ovk;
    libzprime::SaplingNote note;
    std::array<unsigned char, ZC_MEMO_SIZE> memo;

    OutputDescriptionInfo(
        uint256 ovk,
        libzprime::SaplingNote note,
        std::array<unsigned char, ZC_MEMO_SIZE> memo) : ovk(ovk), note(note), memo(memo) {}
};

struct TransparentInputInfo {
    CScript scriptPubKey;
    CAmount value;

    TransparentInputInfo(
        CScript scriptPubKey,
        CAmount value) : scriptPubKey(scriptPubKey), value(value) {}
};

class TransactionBuilderResult {
private:
    boost::optional<CTransaction> maybeTx;
    boost::optional<std::string> maybeError;
public:
    TransactionBuilderResult() = delete;
    TransactionBuilderResult(const CTransaction& tx);
    TransactionBuilderResult(const std::string& error);
    bool IsTx();
    bool IsError();
    CTransaction GetTxOrThrow();
    std::string GetError();
};

class TransactionBuilder
{
private:
    Consensus::Params consensusParams;
    int nHeight;
    const CKeyStore* keystore;
    ZCJoinSplit* sproutParams;
    const CCoinsViewCache* coinsView;
    CCriticalSection* cs_coinsView;
    CMutableTransaction mtx;
    CAmount fee = 10000;

    std::vector<SpendDescriptionInfo> spends;
    std::vector<OutputDescriptionInfo> outputs;
    std::vector<libzprime::JSInput> jsInputs;
    std::vector<libzprime::JSOutput> jsOutputs;
    std::vector<TransparentInputInfo> tIns;

    boost::optional<std::pair<uint256, libzprime::SaplingPaymentAddress>> saplingChangeAddr;
    boost::optional<libzprime::SproutPaymentAddress> sproutChangeAddr;
    boost::optional<CTxDestination> tChangeAddr;

public:
    TransactionBuilder() {}
    TransactionBuilder(
        const Consensus::Params& consensusParams,
        int nHeight,
        CKeyStore* keyStore = nullptr,
        ZCJoinSplit* sproutParams = nullptr,
        CCoinsViewCache* coinsView = nullptr,
        CCriticalSection* cs_coinsView = nullptr);

    void SetFee(CAmount fee);

    // Throws if the anchor does not match the anchor used by
    // previously-added Sapling spends.
    void AddSaplingSpend(
        libzprime::SaplingExpandedSpendingKey expsk,
        libzprime::SaplingNote note,
        uint256 anchor,
        SaplingWitness witness);

    void AddSaplingOutput(
        uint256 ovk,
        libzprime::SaplingPaymentAddress to,
        CAmount value,
        std::array<unsigned char, ZC_MEMO_SIZE> memo = {{0xF6}});

    // Throws if the anchor does not match the anchor used by
    // previously-added Sprout inputs.
    void AddSproutInput(
        libzprime::SproutSpendingKey sk,
        libzprime::SproutNote note,
        SproutWitness witness);

    void AddSproutOutput(
        libzprime::SproutPaymentAddress to,
        CAmount value,
        std::array<unsigned char, ZC_MEMO_SIZE> memo = {{0xF6}});

    // Assumes that the value correctly corresponds to the provided UTXO.
    void AddTransparentInput(COutPoint utxo, CScript scriptPubKey, CAmount value);

    void AddTransparentOutput(CTxDestination& to, CAmount value);

    void SendChangeTo(libzprime::SaplingPaymentAddress changeAddr, uint256 ovk);

    void SendChangeTo(libzprime::SproutPaymentAddress);

    void SendChangeTo(CTxDestination& changeAddr);

    TransactionBuilderResult Build();

private:
    void CreateJSDescriptions();

    void CreateJSDescription(
        uint64_t vpub_old,
        uint64_t vpub_new,
        std::array<libzprime::JSInput, ZC_NUM_JS_INPUTS> vjsin,
        std::array<libzprime::JSOutput, ZC_NUM_JS_OUTPUTS> vjsout,
        std::array<size_t, ZC_NUM_JS_INPUTS>& inputMap,
        std::array<size_t, ZC_NUM_JS_OUTPUTS>& outputMap);
};

#endif /* TRANSACTION_BUILDER_H */
