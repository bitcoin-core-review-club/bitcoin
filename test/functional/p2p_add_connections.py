#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test add_outbound_p2p_connection test framework functionality"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.p2p import P2PInterface
from test_framework.util import assert_equal


class P2PAddConnections(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = False
        self.num_nodes = 2

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.disconnect_nodes(0, 1)

        self.log.info("Add 8 outbounds to node 0")
        for i in range(8):
            self.log.info("outbound: {}".format(i))
            self.nodes[0].add_outbound_p2p_connection(P2PInterface())

        self.log.info("Add 2 block-relay-only connections to node 0")
        for i in range(2):
            self.log.info("block-relay-only: {}".format(i))
            self.nodes[0].add_outbound_p2p_connection(P2PInterface(), connection_type="blockrelay")

        self.log.info("Add 2 block-relay-only connections to node 1")
        for i in range(2):
            self.log.info("block-relay-only: {}".format(i))
            self.nodes[1].add_outbound_p2p_connection(P2PInterface(), connection_type="blockrelay")

        self.log.info("Add some inbound connections to node 1")
        for i in range(5):
            self.log.info("inbound: {}".format(i))
            self.nodes[1].add_p2p_connection(P2PInterface())

        self.log.info("Add 8 outbounds to node 1")
        for i in range(8):
            self.log.info("outbound: {}".format(i))
            self.nodes[1].add_outbound_p2p_connection(P2PInterface())

        self.log.info("Check the connections opened as expected")
        assert_equal(len(self.nodes[0].getpeerinfo()), 10)
        assert_equal(len(self.nodes[1].getpeerinfo()), 15)

        # check node0 has all outbound connections
        node0_peers = []
        for i in range(10):
            node0_peers.append(self.nodes[0].getpeerinfo()[i]['inbound'])
        assert_equal(node0_peers.count(False), 10)

        # check node1 has 10 outbounds & 5 inbounds
        node1_peers = []
        for i in range(15):
            node1_peers.append(self.nodes[1].getpeerinfo()[i]['inbound'])

        assert_equal(node1_peers.count(False), 10)
        assert_equal(node1_peers.count(True), 5)

        self.log.info("Disconnect p2p connections & try to re-open")
        self.nodes[0].disconnect_p2ps()

        self.log.info("Add 8 outbounds to node 0")
        for i in range(8):
            self.log.info("outbound: {}".format(i))
            self.nodes[0].add_outbound_p2p_connection(P2PInterface())

        self.log.info("Add 2 block-relay-only connections to node 0")
        for i in range(2):
            self.log.info("block-relay-only: {}".format(i))
            self.nodes[0].add_outbound_p2p_connection(P2PInterface(), connection_type="blockrelay")

        self.log.info("Restart node 0 and try to reconnect to p2ps")
        self.restart_node(0)

        self.log.info("Add 8 outbounds to node 0")
        for i in range(8):
            self.log.info("outbound: {}".format(i))
            self.nodes[0].add_outbound_p2p_connection(P2PInterface())

        self.log.info("Add 2 block-relay-only connections to node 0")
        for i in range(2):
            self.log.info("block-relay-only: {}".format(i))
            self.nodes[0].add_outbound_p2p_connection(P2PInterface(), connection_type="blockrelay")


if __name__ == '__main__':
    P2PAddConnections().main()
