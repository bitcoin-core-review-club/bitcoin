// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <net.h>
#include <protocol.h>
#include <test/fuzz/fuzz.h>

#include <cassert>
#include <cstdint>
#include <memory>
#include <limits>
#include <vector>

void initialize()
{
    SelectParams(CBaseChainParams::REGTEST);
}

void test_deserializer(std::unique_ptr<TransportDeserializer>& deserializer, const std::vector<uint8_t>& buffer, const int header_size)
{
    const char* pch = (const char*)buffer.data();
    size_t n_bytes = buffer.size();
    while (n_bytes > 0) {
        const int handled = deserializer->Read(pch, n_bytes);
        if (handled < 0) {
            break;
        }
        pch += handled;
        n_bytes -= handled;
        if (deserializer->Complete()) {
            const int64_t m_time = std::numeric_limits<int64_t>::max();
            const CNetMessage msg = deserializer->GetMessage(Params().MessageStart(), m_time);
            assert(msg.m_command.size() <= CMessageHeader::COMMAND_SIZE);
            assert(msg.m_raw_message_size <= buffer.size());
            assert(msg.m_raw_message_size == header_size + msg.m_message_size);
            assert(msg.m_time == m_time);
            if (msg.m_valid_header) {
                assert(msg.m_valid_netmagic);
            }
            if (!msg.m_valid_netmagic) {
                assert(!msg.m_valid_header);
            }
        }
    }
}

void test_one_input(const std::vector<uint8_t>& buffer)
{
#if V1_FUZZ
    std::unique_ptr<TransportDeserializer> v1_deserializer = MakeUnique<V1TransportDeserializer>(Params().MessageStart(), SER_NETWORK, INIT_PROTO_VERSION);
    test_deserializer(v1_deserializer, buffer, CMessageHeader::HEADER_SIZE);
#elif V2_FUZZ
    const CPrivKey k1(32, 0);
    const CPrivKey k2(32, 0);
    const uint256 session_id;
    std::unique_ptr<TransportDeserializer> v2_deserializer = MakeUnique<V2TransportDeserializer>(V2TransportDeserializer(k1, k2, session_id));
    test_deserializer(v2_deserializer, buffer, CHACHA20_POLY1305_AEAD_AAD_LEN + CHACHA20_POLY1305_AEAD_TAG_LEN);
#else
#error Need at least one fuzz target to compile
#endif
}
