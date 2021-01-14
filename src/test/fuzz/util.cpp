// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/util.h>
#include <version.h>

void FillNode(FuzzedDataProvider& fuzzed_data_provider, CNode& node, bool init_version) noexcept
{
    const ServiceFlags remote_services = ConsumeWeakEnum(fuzzed_data_provider, ALL_SERVICE_FLAGS);
    const NetPermissionFlags permission_flags = ConsumeWeakEnum(fuzzed_data_provider, ALL_NET_PERMISSION_FLAGS);
    const int32_t version = fuzzed_data_provider.ConsumeIntegralInRange<int32_t>(MIN_PEER_PROTO_VERSION, std::numeric_limits<int32_t>::max());
    const bool filter_txs = fuzzed_data_provider.ConsumeBool();

    node.nServices = remote_services;
    node.m_permissionFlags = permission_flags;
    if (init_version) {
        node.nVersion = version;
        node.SetCommonVersion(std::min(version, PROTOCOL_VERSION));
    }
    if (node.m_tx_relay != nullptr) {
        LOCK(node.m_tx_relay->cs_filter);
        node.m_tx_relay->fRelayTxes = filter_txs;
    }
}

CMutableTransaction ConsumeTransaction(FuzzedDataProvider& fuzzed_data_provider, const std::optional<std::vector<uint256>>& prevout_txids, const int max_num_in, const int max_num_out) noexcept
{
    CMutableTransaction tx_mut;
    tx_mut.nVersion = fuzzed_data_provider.ConsumeBool() ?
                          CTransaction::CURRENT_VERSION :
                          fuzzed_data_provider.ConsumeIntegral<int32_t>();
    tx_mut.nLockTime = fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    const auto num_in = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, max_num_in);
    const auto num_out = fuzzed_data_provider.ConsumeIntegralInRange<int>(0, max_num_out);
    for (int i = 0; i < num_in; ++i) {
        const auto& txid_prev = prevout_txids ?
                                    prevout_txids->at(fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, prevout_txids->size() - 1)) :
                                    ConsumeUInt256(fuzzed_data_provider);
        const auto index_out = fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(0, max_num_out);
        const auto sequence = fuzzed_data_provider.ConsumeBool() ?
                                  fuzzed_data_provider.PickValueInArray({CTxIn::SEQUENCE_FINAL, CTxIn::SEQUENCE_FINAL - 1}) :
                                  fuzzed_data_provider.ConsumeIntegral<uint32_t>();
        const auto script_sig = ConsumeScript(fuzzed_data_provider);
        const auto script_wit = ConsumeScriptWitness(fuzzed_data_provider);
        CTxIn in;
        in.prevout = COutPoint{txid_prev, index_out};
        in.nSequence = sequence;
        in.scriptSig = script_sig;
        in.scriptWitness = script_wit;

        tx_mut.vin.push_back(in);
    }
    for (int i = 0; i < num_out; ++i) {
        const auto amount = fuzzed_data_provider.ConsumeIntegralInRange<CAmount>(-10, 50 * COIN + 10);
        const auto script_pk = ConsumeScript(fuzzed_data_provider, /* max_length */ 128, /* maybe_p2wsh */ true);
        tx_mut.vout.emplace_back(amount, script_pk);
    }
    return tx_mut;
}

CScriptWitness ConsumeScriptWitness(FuzzedDataProvider& fuzzed_data_provider, const size_t max_stack_elem_size) noexcept
{
    CScriptWitness ret;
    const auto n_elements = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(0, max_stack_elem_size);
    for (size_t i = 0; i < n_elements; ++i) {
        ret.stack.push_back(ConsumeRandomLengthByteVector(fuzzed_data_provider));
    }
    return ret;
}

CScript ConsumeScript(FuzzedDataProvider& fuzzed_data_provider, const size_t max_length, const bool maybe_p2wsh) noexcept
{
    const std::vector<uint8_t> b = ConsumeRandomLengthByteVector(fuzzed_data_provider);
    CScript r_script{b.begin(), b.end()};
    if (maybe_p2wsh && fuzzed_data_provider.ConsumeBool()) {
        uint256 script_hash;
        CSHA256().Write(&r_script[0], r_script.size()).Finalize(script_hash.begin());
        r_script.clear();
        r_script << OP_0 << ToByteVector(script_hash);
    }
    return r_script;
}
