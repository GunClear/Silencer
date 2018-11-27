#!python
import argparse
from eth_utils import keccak, to_bytes, to_hex


def to_bytes32(value: int) -> bytes:
    v = to_bytes(value).rjust(32, b'\x00')
    assert len(v) == 32, \
            "{} must be less than 2**256".format(value)
    return v


def create_token_id(randomizer, serial) -> hex:
    return to_hex(keccak(to_bytes32(serial) + to_bytes32(randomizer)))


if __name__ == '__main__':
    ap = argparse.ArgumentParser("Generate Token Hash for Silencer")
    ap.add_argument("randomizer", type=int, help="Firearm Serial Number")
    ap.add_argument("serial", type=int, help="Firearm Token Randomizer")
    args = ap.parse_args()
    print(create_token_id(args.randomizer, args.serial))
