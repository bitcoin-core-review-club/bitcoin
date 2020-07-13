#!/usr/bin/env python3
# Copyright (c) 2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Parse message log binary files.  To be used in conjunction with -logmessages."""

import argparse
import os
import sys
from io import BytesIO
import json
from pathlib import Path
from typing import Any, List

sys.path.append(os.path.join(os.path.dirname(__file__), '../../test/functional'))

from test_framework.messages import ser_uint256     # noqa: E402
from test_framework.mininode import MESSAGEMAP      # noqa: E402
from test_framework.util import assert_equal        # noqa: E402

TIME_SIZE = 8
LENGTH_SIZE = 4
MSGTYPE_SIZE = 12

# The test framework classes stores hashes as large ints in many cases.
# There isn't a way to distinguish between a large int and a large int that is actually a blob of bytes.
# As such, they are itemized here
# (These can be easily found by looking for calls to deser_uint256, deser_uint256_vector, and uint256_from_str in messages.py)
HASH_INTS = [
    "blockhash",
    "block_hash",
    "hash",     # A few conflicts here
    "hashMerkleRoot",
    "hashPrevBlock",
    "hashstop",
    "prev_header",
    "sha256",
    "stop_hash",
]

HASH_INT_VECTORS = [
    "hashes",
    "headers",  # One conflict here
    "vHave",
    "vHash",
]

def to_jsonable(obj: Any) -> Any:
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    elif hasattr(obj, "__slots__"):
        ret = {}    # type: Any
        for slot in obj.__slots__:
            val = getattr(obj, slot, None)
            if slot in HASH_INTS and isinstance(val, int):
                ret[slot] = ser_uint256(val).hex()
            elif slot in HASH_INT_VECTORS and isinstance(val[0], int):
                ret[slot] = [ser_uint256(a).hex() for a in val]
            else:
                ret[slot] = to_jsonable(val)
        return ret
    elif isinstance(obj, list):
        return [to_jsonable(a) for a in obj]
    elif isinstance(obj, bytes):
        return obj.hex()
    else:
        return obj


def process_file(path: str, messages: List[Any], recv: bool) -> None:
    with open(path, 'rb') as f_in:
        while True:
            tmp_header_raw = f_in.read(TIME_SIZE + LENGTH_SIZE + MSGTYPE_SIZE)
            if not tmp_header_raw:
                break
            tmp_header = BytesIO(tmp_header_raw)
            time = int.from_bytes(tmp_header.read(TIME_SIZE), "little")      # type: int
            msgtype = tmp_header.read(MSGTYPE_SIZE).split(b'\x00', 1)[0]     # type: bytes
            length = int.from_bytes(tmp_header.read(LENGTH_SIZE), "little")  # type: int
            if msgtype not in MESSAGEMAP:
                # For now just skip unrecognized messages
                f_in.read(length)
                continue
            payload_start_pos = f_in.tell()
            msg = MESSAGEMAP[msgtype]()
            msg.deserialize(f_in)
            payload_length = f_in.tell() - payload_start_pos
            assert_equal(length, payload_length)
            msg_dict = {}
            msg_dict["msgtype"] = getattr(msg, "msgtype", None).decode()
            msg_dict["direction"] = "recv" if recv else "sent"
            msg_dict["time"] = time
            msg_dict["size"] = length   # "size" is less readable here, but more readable in the output
            if length:
                msg_dict["body"] = to_jsonable(msg)
            messages.append(msg_dict)


def main():
    """Main"""
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="EXAMPLE \n\t{0} -o out.json <data-dir>/message_logging/**/*.dat".format(sys.argv[0]),
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        "logpaths", nargs='+',
        help="binary message dump files to parse.")
    parser.add_argument("-o", "--output", help="output file.  If unset print to stdout")
    args = parser.parse_args()
    logpaths = [Path.cwd() / Path(logpath) for logpath in args.logpaths]
    output = Path.cwd() / Path(args.output) if args.output else False

    messages = []   # type: List[Any]
    for log in logpaths:
        process_file(str(log), messages, "recv" in log.stem)

    messages.sort(key=lambda msg: msg['time'])

    jsonrep = json.dumps(messages)
    if output:
        with open(str(output), 'w+', encoding="utf8") as f_out:
            f_out.write(jsonrep)
    else:
        print(jsonrep)

if __name__ == "__main__":
    main()
