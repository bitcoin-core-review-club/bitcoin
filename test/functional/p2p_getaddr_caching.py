#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Test addr response caching
"""

from test_framework.messages import (
    CAddress,
    NODE_NETWORK,
    NODE_WITNESS,
    msg_addr,
    msg_getaddr,
)
from test_framework.mininode import (
    P2PInterface,
    mininode_lock
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    wait_until
)
import time

ADDRS = []
for i in range(1000):
    addr = CAddress()
    addr.time = int(time.time())
    addr.nServices = NODE_NETWORK | NODE_WITNESS
    third_octet = int(i / 256) % 256
    fourth_octet = i % 256
    addr.ip = "123.123.{}.{}".format(third_octet, fourth_octet)
    addr.port = 8333
    ADDRS.append(addr)

class AddrReceiver(P2PInterface):

    def __init__(self):
        super().__init__()
        self.received_addrs = None

    def on_addr(self, message):
        self.received_addrs = []
        for addr in message.addrs:
            self.received_addrs.append(addr.ip)

    def received_addr(self):
        return self.received_addrs is not None


class AddrTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = False
        self.num_nodes = 1

    def run_test(self):
        self.log.info('Create connection that sends and requests addr messages')
        addr_source = self.nodes[0].add_p2p_connection(P2PInterface())
        msg_send_addrs = msg_addr()

        self.log.info('Fill peer AddrMan with a lot of records')
        msg_send_addrs.addrs = ADDRS
        with self.nodes[0].assert_debug_log([
                'Added 1000 addresses from 127.0.0.1: 0 tried',
                'received: addr (30003 bytes) peer=0',
        ]):
            addr_source.send_and_ping(msg_send_addrs)

        responses = []
        self.log.info('Send many addr requests within short time to receive same response')
        N = 5
        cur_mock_time = int(time.time())
        for i in range(N):
            addr_receiver = self.nodes[0].add_p2p_connection(AddrReceiver())
            with self.nodes[0].assert_debug_log([
                    "received: getaddr (0 bytes) peer={}".format(i+1),
            ]):
                addr_receiver.send_and_ping(msg_getaddr())
                # Trigger response
                cur_mock_time += 5 * 60
                self.nodes[0].setmocktime(cur_mock_time)
                wait_until(addr_receiver.received_addr, timeout=30, lock=mininode_lock)
                responses.append(addr_receiver.received_addrs)
        for response in responses[1:]:
            assert_equal(response, responses[0])

        cur_mock_time += 3 * 24 * 60 * 60
        self.nodes[0].setmocktime(cur_mock_time)

        self.log.info('After time passed, see a new response to addr request')
        last_addr_receiver = self.nodes[0].add_p2p_connection(AddrReceiver())
        with self.nodes[0].assert_debug_log([
                "received: getaddr (0 bytes) peer={}".format(N+1),
        ]):
            last_addr_receiver.send_and_ping(msg_getaddr())
            # Trigger response
            cur_mock_time += 5 * 60
            self.nodes[0].setmocktime(cur_mock_time)
            wait_until(last_addr_receiver.received_addr, timeout=30, lock=mininode_lock)
            # new response is different
            assert(set(responses[0]) != set(last_addr_receiver.received_addrs))


if __name__ == '__main__':
    AddrTest().main()
