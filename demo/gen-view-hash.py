#!python
import argparse
from eth_utils import keccak, to_bytes, to_canonical_address, to_hex


def to_bytes32(value: int) -> bytes:
    v = to_bytes(value).rjust(32, b'\x00')
    assert len(v) == 32, \
            "{} must be less than 2**256".format(value)
    return v


def create_view_hash(acct, authroot_hash, randomizer) -> hex:
    acct_bytes = to_canonical_address(acct)
    authroot_hash_bytes = to_bytes(hexstr=authroot_hash)
    randomizer_bytes = to_bytes32(randomizer)
    return to_hex(keccak(acct_bytes+authroot_hash_bytes+randomizer_bytes))


if __name__ == '__main__':
    ap = argparse.ArgumentParser("Generate Token Hash for Silencer")
    ap.add_argument("acct", type=str, help="Account's 20-byte Ethereum address")
    ap.add_argument("authroot_hash", type=str, help="Authorization Merkle Root")
    ap.add_argument("randomizer", type=int, help="Account View Randomizer")
    args = ap.parse_args()
    print(create_view_hash(args.acct, args.authroot_hash, args.randomizer))
