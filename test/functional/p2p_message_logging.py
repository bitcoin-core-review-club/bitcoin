#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test per-peer message logging capability.

Additionally, the output of contrib/message-logging/message-logging-parser.py should be verified manually.
"""

import glob
from io import BytesIO
import os

from test_framework.mininode import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

TIME_SIZE = 8
LENGTH_SIZE = 4
MSGTYPE_SIZE = 12

def mini_parser(dat_file):
    """Parse a data file created by LogMessage.

    From the data file we'll only check the structure.

    We won't care about things like:
    - Deserializing the payload of the message
        - This is managed by the deserialize methods in test_framework.messages
    - The order of the messages
        - There's no reason why we can't, say, change the order of the messages in the handshake
    - Message Type
        - We can add new message types

    We're ignoring these because they're simply too brittle to test here.
    """
    with open(dat_file, 'rb') as f_in:
        while True:
            tmp_header_raw = f_in.read(TIME_SIZE + LENGTH_SIZE + MSGTYPE_SIZE)
            if not tmp_header_raw:
                break
            tmp_header = BytesIO(tmp_header_raw)
            time = int.from_bytes(tmp_header.read(TIME_SIZE), "little")      # type: int
            assert(time >= 1231006505000000)   # genesis block timestamp
            msgtype = tmp_header.read(MSGTYPE_SIZE).split(b'\x00', 1)[0]     # type: bytes
            assert(len(msgtype) > 0)
            length = int.from_bytes(tmp_header.read(LENGTH_SIZE), "little")  # type: int
            data = f_in.read(length)
            assert_equal(len(data), length)


class MessageLoggingTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-logmessages"]]
        self.setup_clean_chain = True

    def run_test(self):
        logdir = os.path.join(self.nodes[0].datadir, "regtest/message_logging")
        # Connect an disconnect a node so that the handshake occurs
        self.nodes[0].add_p2p_connection(P2PDataStore())
        self.nodes[0].disconnect_p2ps()
        recv_file = glob.glob(os.path.join(logdir, "*/msgs_recv.dat"))[0]
        mini_parser(recv_file)
        sent_file = glob.glob(os.path.join(logdir, "*/msgs_sent.dat"))[0]
        mini_parser(sent_file)


if __name__ == '__main__':
    MessageLoggingTest().main()
