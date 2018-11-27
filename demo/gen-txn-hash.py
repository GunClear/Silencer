#!python
import argparse
from eth_utils import keccak, to_bytes, to_canonical_address, to_hex


def to_bytes32(value: int) -> bytes:
    v = to_bytes(value).rjust(32, b'\x00')
    assert len(v) == 32, \
            "{} must be less than 2**256".format(value)
    return v


def create_txn_hash(sender_acct, receiver_key, token_hash, authroot_hash) -> hex:
    sender_acct_bytes = to_canonical_address(sender_acct)
    receiver_key_bytes = to_bytes32(receiver_key)
    token_hash_bytes = to_bytes(hexstr=token_hash)
    authroot_hash_bytes = to_bytes(hexstr=authroot_hash)
    return to_hex(keccak(sender_acct_bytes+receiver_key_bytes+token_hash_bytes+authroot_hash_bytes))


if __name__ == '__main__':
    ap = argparse.ArgumentParser("Generate Token Hash for Silencer")
    ap.add_argument("sender_acct", type=str, help="Sender's 20-byte Ethereum address")
    ap.add_argument("receiver_key", type=int, help="Receiver's Secret key")
    ap.add_argument("token_hash", type=str, help="32-byte Token UID")
    ap.add_argument("authroot_hash", type=str, help="Authorization Merkle Root")
    args = ap.parse_args()
    print(create_txn_hash(args.sender_acct, args.receiver_key, args.token_hash, args.authroot_hash))
