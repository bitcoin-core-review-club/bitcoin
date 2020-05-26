// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/coinstats.h>

#include <coins.h>
#include <crypto/muhash.h>
#include <hash.h>
#include <serialize.h>
#include <uint256.h>
#include <util/system.h>
#include <validation.h>

#include <map>

uint64_t GetBogoSize(const CScript& scriptPubKey) {
    return 32 /* txid */ +
           4 /* vout index */ +
           4 /* height + coinbase */ +
           8 /* amount */ +
           2 /* scriptPubKey len */ +
           scriptPubKey.size() /* scriptPubKey */;
}

static void ApplyStats(CCoinsStats &stats, MuHash3072& muhash, const uint256& hash, const std::map<uint32_t, Coin>& outputs)
{
    assert(!outputs.empty());
    stats.nTransactions++;
    for (const auto& output : outputs) {
        COutPoint outpoint = COutPoint(hash, output.first);
        Coin coin = output.second;

        TruncatedSHA512Writer ss(SER_DISK, 0);
        ss << outpoint;
        ss << (uint32_t)(coin.nHeight * 2 + coin.fCoinBase);
        ss << coin.out;
        muhash *= MuHash3072(ss.GetHash().begin());

        stats.nTransactionOutputs++;
        stats.nTotalAmount += output.second.out.nValue;
        stats.nBogoSize += GetBogoSize(output.second.out.scriptPubKey);
    }
}

static void ApplyStats(CCoinsStats &stats, CHashWriter& ss, const uint256& hash, const std::map<uint32_t, Coin>& outputs)
{
    assert(!outputs.empty());
    ss << hash;
    ss << VARINT(outputs.begin()->second.nHeight * 2 + outputs.begin()->second.fCoinBase ? 1u : 0u);
    stats.nTransactions++;
    for (const auto& output : outputs) {
        ss << VARINT(output.first + 1);
        ss << output.second.out.scriptPubKey;
        ss << VARINT_MODE(output.second.out.nValue, VarIntMode::NONNEGATIVE_SIGNED);
        stats.nTransactionOutputs++;
        stats.nTotalAmount += output.second.out.nValue;
        stats.nBogoSize += GetBogoSize(output.second.out.scriptPubKey);
    }
    ss << VARINT(0u);
}

//! Calculate statistics about the unspent transaction output set
template <typename T>
bool GetUTXOStats(CCoinsView* view, CCoinsStats& stats, const std::function<void()>& interruption_point, T hash)
{
    stats = CCoinsStats();
    std::unique_ptr<CCoinsViewCursor> pcursor(view->Cursor());
    assert(pcursor);

    stats.hashBlock = pcursor->GetBestBlock();
    {
        LOCK(cs_main);
        stats.nHeight = LookupBlockIndex(stats.hashBlock)->nHeight;
    }

    PrepareHash(hash, stats);

    uint256 prevkey;
    std::map<uint32_t, Coin> outputs;
    while (pcursor->Valid()) {
        interruption_point();
        COutPoint key;
        Coin coin;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            if (!outputs.empty() && key.hash != prevkey) {
                ApplyStats(stats, hash, prevkey, outputs);
                outputs.clear();
            }
            prevkey = key.hash;
            outputs[key.n] = std::move(coin);
            stats.coins_count++;
        } else {
            return error("%s: unable to read value", __func__);
        }
        pcursor->Next();
    }
    if (!outputs.empty()) {
        ApplyStats(stats, hash, prevkey, outputs);
    }

    FinalizeHash(hash, stats);

    stats.nDiskSize = view->EstimateSize();
    return true;
}

// The legacy hash serializes the hashBlock
void PrepareHash(CHashWriter& hash, CCoinsStats& stats) {
    hash << stats.hashBlock;
}
// Muhash does not need the prepare step
void PrepareHash(MuHash3072 hash, CCoinsStats& stats) {}

void FinalizeHash(CHashWriter& hash, CCoinsStats& stats) {
    stats.hashSerialized = hash.GetHash();
}
void FinalizeHash(MuHash3072 hash, CCoinsStats& stats) {
    unsigned char out[384];
    hash.Finalize(out);
    stats.hashSerialized = (TruncatedSHA512Writer(SER_DISK, 0) << out).GetHash();
}

bool GetUTXOStats(CCoinsView *view, CCoinsStats &stats, const std::function<void()>& interruption_point, bool use_muhash)
{
    if (use_muhash) {
        MuHash3072 muhash;
        return GetUTXOStats(view, stats, interruption_point, muhash);
    } else {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        return GetUTXOStats(view, stats, interruption_point, ss);
    }
}
