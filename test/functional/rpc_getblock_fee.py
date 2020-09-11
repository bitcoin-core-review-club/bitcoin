#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''Test getblock rpc fee calculation.
'''

import os

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import get_datadir_path


class GetblockFeeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        address = node.getnewaddress()
        node.generatetoaddress(101, address)
        node.sendtoaddress(address, 1)
        blockhash = node.generatetoaddress(1, address)[0]

        self.log.info('Ensure that getblock with verbosity 2 includes fee')
        block = node.getblock(blockhash, 2)
        assert 'fee' in block['tx'][1]

        self.log.info('Ensure that getblock with verbosity 1 doesn\'t include fee')
        block = node.getblock(blockhash, 1)
        assert 'fee' not in block['tx'][1]

        self.log.info('Ensure that getblock doesn\'t crash or include fee if undo data is missing')
        datadir = get_datadir_path(self.options.tmpdir, 0)
        os.unlink(os.path.join(datadir, self.chain, 'blocks', 'rev00000.dat'))
        block = node.getblock(blockhash, 2)
        assert 'fee' not in block['tx'][1]


if __name__ == '__main__':
    GetblockFeeTest().main()
