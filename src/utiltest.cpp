// Copyright (c) 2016 The zPrime developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utiltest.h"

#include "consensus/upgrades.h"
#include "transaction_builder.h"

#include <array>

// Sprout
CMutableTransaction GetValidSproutReceiveTransaction(ZCJoinSplit& params,
                                const libzprime::SproutSpendingKey& sk,
                                CAmount value,
                                bool randomInputs,
                                int32_t version /* = 2 */) {
    CMutableTransaction mtx;
    mtx.nVersion = version;
    mtx.vin.resize(2);
    if (randomInputs) {
        mtx.vin[0].prevout.hash = GetRandHash();
        mtx.vin[1].prevout.hash = GetRandHash();
    } else {
        mtx.vin[0].prevout.hash = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
        mtx.vin[1].prevout.hash = uint256S("0000000000000000000000000000000000000000000000000000000000000002");
    }
    mtx.vin[0].prevout.n = 0;
    mtx.vin[1].prevout.n = 0;

    // Generate an ephemeral keypair.
    uint256 joinSplitPubKey;
    unsigned char joinSplitPrivKey[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(joinSplitPubKey.begin(), joinSplitPrivKey);
    mtx.joinSplitPubKey = joinSplitPubKey;

    std::array<libzprime::JSInput, 2> inputs = {
        libzprime::JSInput(), // dummy input
        libzprime::JSInput() // dummy input
    };

    std::array<libzprime::JSOutput, 2> outputs = {
        libzprime::JSOutput(sk.address(), value),
        libzprime::JSOutput(sk.address(), value)
    };

    // Prepare JoinSplits
    uint256 rt;
    JSDescription jsdesc {false, params, mtx.joinSplitPubKey, rt,
                          inputs, outputs, 2*value, 0, false};
    mtx.vjoinsplit.push_back(jsdesc);

    // Consider: The following is a bit misleading (given the name of this function)
    // and should perhaps be changed, but currently a few tests in test_wallet.cpp
    // depend on this happening.
    if (version >= 4) {
        // Shielded Output
        OutputDescription od;
        mtx.vShieldedOutput.push_back(od);
    }

    // Empty output script.
    uint32_t consensusBranchId = SPROUT_BRANCH_ID;
    CScript scriptCode;
    CTransaction signTx(mtx);
    uint256 dataToBeSigned = SignatureHash(scriptCode, signTx, NOT_AN_INPUT, SIGHASH_ALL, 0, consensusBranchId);

    // Add the signature
    assert(crypto_sign_detached(&mtx.joinSplitSig[0], NULL,
                                dataToBeSigned.begin(), 32,
                                joinSplitPrivKey
                               ) == 0);

    return mtx;
}

CWalletTx GetValidSproutReceive(ZCJoinSplit& params,
                                const libzprime::SproutSpendingKey& sk,
                                CAmount value,
                                bool randomInputs,
                                int32_t version /* = 2 */)
{
    CMutableTransaction mtx = GetValidSproutReceiveTransaction(
        params, sk, value, randomInputs, version
    );
    CTransaction tx {mtx};
    CWalletTx wtx {NULL, tx};
    return wtx;
}

CWalletTx GetInvalidCommitmentSproutReceive(ZCJoinSplit& params,
                                const libzprime::SproutSpendingKey& sk,
                                CAmount value,
                                bool randomInputs,
                                int32_t version /* = 2 */)
{
    CMutableTransaction mtx = GetValidSproutReceiveTransaction(
        params, sk, value, randomInputs, version
    );
    mtx.vjoinsplit[0].commitments[0] = uint256();
    mtx.vjoinsplit[0].commitments[1] = uint256();
    CTransaction tx {mtx};
    CWalletTx wtx {NULL, tx};
    return wtx;
}

libzprime::SproutNote GetSproutNote(ZCJoinSplit& params,
                                   const libzprime::SproutSpendingKey& sk,
                                   const CTransaction& tx, size_t js, size_t n) {
    ZCNoteDecryption decryptor {sk.receiving_key()};
    auto hSig = tx.vjoinsplit[js].h_sig(params, tx.joinSplitPubKey);
    auto note_pt = libzprime::SproutNotePlaintext::decrypt(
        decryptor,
        tx.vjoinsplit[js].ciphertexts[n],
        tx.vjoinsplit[js].ephemeralKey,
        hSig,
        (unsigned char) n);
    return note_pt.note(sk.address());
}

CWalletTx GetValidSproutSpend(ZCJoinSplit& params,
                              const libzprime::SproutSpendingKey& sk,
                              const libzprime::SproutNote& note,
                              CAmount value) {
    CMutableTransaction mtx;
    mtx.vout.resize(2);
    mtx.vout[0].nValue = value;
    mtx.vout[1].nValue = 0;

    // Generate an ephemeral keypair.
    uint256 joinSplitPubKey;
    unsigned char joinSplitPrivKey[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(joinSplitPubKey.begin(), joinSplitPrivKey);
    mtx.joinSplitPubKey = joinSplitPubKey;

    // Fake tree for the unused witness
    SproutMerkleTree tree;

    libzprime::JSOutput dummyout;
    libzprime::JSInput dummyin;

    {
        if (note.value() > value) {
            libzprime::SproutSpendingKey dummykey = libzprime::SproutSpendingKey::random();
            libzprime::SproutPaymentAddress dummyaddr = dummykey.address();
            dummyout = libzprime::JSOutput(dummyaddr, note.value() - value);
        } else if (note.value() < value) {
            libzprime::SproutSpendingKey dummykey = libzprime::SproutSpendingKey::random();
            libzprime::SproutPaymentAddress dummyaddr = dummykey.address();
            libzprime::SproutNote dummynote(dummyaddr.a_pk, (value - note.value()), uint256(), uint256());
            tree.append(dummynote.cm());
            dummyin = libzprime::JSInput(tree.witness(), dummynote, dummykey);
        }
    }

    tree.append(note.cm());

    std::array<libzprime::JSInput, 2> inputs = {
        libzprime::JSInput(tree.witness(), note, sk),
        dummyin
    };

    std::array<libzprime::JSOutput, 2> outputs = {
        dummyout, // dummy output
        libzprime::JSOutput() // dummy output
    };

    // Prepare JoinSplits
    uint256 rt = tree.root();
    JSDescription jsdesc {false, params, mtx.joinSplitPubKey, rt,
                          inputs, outputs, 0, value, false};
    mtx.vjoinsplit.push_back(jsdesc);

    // Empty output script.
    uint32_t consensusBranchId = SPROUT_BRANCH_ID;
    CScript scriptCode;
    CTransaction signTx(mtx);
    uint256 dataToBeSigned = SignatureHash(scriptCode, signTx, NOT_AN_INPUT, SIGHASH_ALL, 0, consensusBranchId);

    // Add the signature
    assert(crypto_sign_detached(&mtx.joinSplitSig[0], NULL,
                                dataToBeSigned.begin(), 32,
                                joinSplitPrivKey
                               ) == 0);
    CTransaction tx {mtx};
    CWalletTx wtx {NULL, tx};
    return wtx;
}

// Sapling
const Consensus::Params& RegtestActivateSapling() {
    SelectParams(CBaseChainParams::REGTEST);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_OVERWINTER, Consensus::NetworkUpgrade::ALWAYS_ACTIVE);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_SAPLING, Consensus::NetworkUpgrade::ALWAYS_ACTIVE);
    return Params().GetConsensus();
}

void RegtestDeactivateSapling() {
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_SAPLING, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
    UpdateNetworkUpgradeParameters(Consensus::UPGRADE_OVERWINTER, Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT);
}

libzprime::SaplingExtendedSpendingKey GetTestMasterSaplingSpendingKey() {
    std::vector<unsigned char, secure_allocator<unsigned char>> rawSeed(32);
    HDSeed seed(rawSeed);
    return libzprime::SaplingExtendedSpendingKey::Master(seed);
}

CKey AddTestCKeyToKeyStore(CBasicKeyStore& keyStore) {
    CKey tsk = DecodeSecret(T_SECRET_REGTEST);
    keyStore.AddKey(tsk);
    return tsk;
}

TestSaplingNote GetTestSaplingNote(const libzprime::SaplingPaymentAddress& pa, CAmount value) {
    // Generate dummy Sapling note
    libzprime::SaplingNote note(pa, value);
    uint256 cm = note.cm().get();
    SaplingMerkleTree tree;
    tree.append(cm);
    return { note, tree };
}

CWalletTx GetValidSaplingReceive(const Consensus::Params& consensusParams,
                                 CBasicKeyStore& keyStore,
                                 const libzprime::SaplingExtendedSpendingKey &sk,
                                 CAmount value) {
    // From taddr
    CKey tsk = AddTestCKeyToKeyStore(keyStore);
    auto scriptPubKey = GetScriptForDestination(tsk.GetPubKey().GetID());
    // To zaddr
    auto fvk = sk.expsk.full_viewing_key();
    auto pa = sk.DefaultAddress();

    auto builder = TransactionBuilder(consensusParams, 1, &keyStore);
    builder.SetFee(0);
    builder.AddTransparentInput(COutPoint(), scriptPubKey, value);
    builder.AddSaplingOutput(fvk.ovk, pa, value, {});

    CTransaction tx = builder.Build().GetTxOrThrow();
    CWalletTx wtx {NULL, tx};
    return wtx;
}
