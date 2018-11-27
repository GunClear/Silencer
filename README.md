# Silencer
Zero-Knowledge Proof lib for Gunero

----

# Installation and Demo

## Installation
```bash
$ mkdir build
$ cd depends
$ git submodule init
$ git submodule update
$ cd libsnark/depends
$ git submodule init
$ git submodule update
$ cd ../../../build
$ cmake ..
$ make
```

## Demo Instructions

1. Generate proving and verifying keys for all circuits
```bash
$ cd demo
$ ../silencer generate --circuit=authorization \
        --proving-key-output=./authorization-pk.json \
        --verifying-key-output=./authorization-vk.json
$ ../silencer generate --circuit=receive \
        --proving-key-output=./receive-pk.json \
        --verifying-key-output=./receive-vk.json
$ ../silencer generate --circuit=spend \
        --proving-key-output=./spend-pk.json \
        --verifying-key-output=./spend-vk.json
```

2. Create a firearm token and previous transaction
```bash
$ echo [PICK RANDOM NUMBER] > ./firearm.rand
$ echo [PICK RANDOM SERIAL] > ./firearm.serial
$ python gen-token.py \
        $(cat ./firearm.rand) \
        $(cat ./firearm.serial) \
        > ./token.hash
$ echo [PICK RANDOM ACCOUNT] > ./previous.acct
$ python gen-txn-hash.py \
        $(cat ./previous.acct) \
        $(cat ./sender.key) \
        $(cat ./token.hash) \
        $(cat ./auth-root.hash) \
        > ./previous-transaction.hash
```

3. Generate authorization proof for both accounts
```bash
$ echo [PICK RANDOM NUMBER] > ./sender-view.rand
$ python gen-view-hash.py \
        $(cat ./sender.acct) \
        $(cat ./auth-root.hash) \
        $(cat ./sender-view.rand) \
        > ./sender-view.hash
$ ../silencer prove --circuit=authorization \
        --proving-key=./authorization-pk.json \
        --auth-root-hash=./auth-root.hash \
        --account-status=1 \
        --account-view-hash=./sender-view.hash \
        --account-private-key=./sender.key \
        --account-view-randomizer=./sender-view.rand \
        --auth-sender-branch=./sender-branch.ls \
        --output=./sender-auth.proof
```
Note: Repeat above steps for `receiver`

4. Receiver generates transaction hash
```bash
$ python gen-txn-hash.py \
        $(cat ./sender.acct) \
        $(cat ./receiver.key) \
        $(cat ./token.hash) \
        $(cat ./auth-root.hash) \
        > ./transaction.hash
```

5. Generate the receiver proof with receiver's account
```bash
$ ../silencer prove --circuit=receive \
        --proving-key=./receive-pk.json \
        --auth-root-hash=./auth-root.hash \
        --token=./token.hash \
        --receiver-view-hash=./receiver-view.hash \
        --sender-view-hash=./sender-view.hash \
        --transaction-hash=./transaction.hash \
        --receiver-private-key=./receiver.key \
        --receiver-view-randomizer=./receiver-view.rand \
        --sender-account=./sender.acct \
        --sender-view-randomizer=./sender-view.rand \
        --firearm-serial=./firearm.serial \
        --firearm-view-randomizer=./firearm.rand \
        --output=./receive.proof
```

6. Generate the spend proof with the sender's acocunt
```bash
$ ../silencer prove --circuit=spend \
        --proving-key=./spend-pk.json \
        --auth-root-hash=./auth-root.hash \
        --token=./token.hash \
        --receiver-view-hash=./receiver-view.hash \
        --sender-view-hash=./sender-view.hash \
        --previous-transaction-hash=./previous-transaction.hash \
        --sender-private-key=./receiver.key \
        --sender-view-randomizer=./sender-view.rand \
        --receiver-view-randomizer=./receiver-view.rand \
        --previous-account=./previous.acct \
        --previous-auth-root-hash=./auth-root.hash
        --output=./spend.proof
```

7. Validate all the proofs
```bash
$ ../silencer verify --circuit=authorization \
        --verifying-key=./authorization-vk.json \
        --auth-root-hash=./auth-root.hash \
        --account-status=1 \
        --account-view-hash=./sender-view.hash \
        --proof=./sender-auth.proof
SUCCESS!
$ ../silencer verify --circuit=authorization \
        --verifying-key=./authorization-vk.json \
        --auth-root-hash=./auth-root.hash \
        --account-status=1 \
        --account-view-hash=./receiver-view.hash \
        --proof=./receiver-auth.proof
SUCCESS!
$ ../silencer verify --circuit=receive \
        --proving-key=./receive-vk.json \
        --auth-root-hash=./auth-root.hash \
        --token=./token.hash \
        --receiver-view-hash=./receiver-view.hash \
        --sender-view-hash=./sender-view.hash \
        --transaction-hash=./transaction.hash \
        --proof=./receive.proof
SUCCESS!
$ ../silencer verify --circuit=spend \
        --proving-key=./spend-vk.json \
        --auth-root-hash=./auth-root.hash \
        --token=./token.hash \
        --receiver-view-hash=./receiver-view.hash \
        --sender-view-hash=./sender-view.hash \
        --previous-transaction-hash=./previous-transaction.hash \
        --proof=./spend.proof
SUCCESS!
```

NOTE: Yes, the proofs do indeed fail if not consistent:
```bash
$ ../silencer verify --circuit=authorization \
        --verifying-key=./authorization-vk.json \
        --auth-root-hash=./auth-root.hash \
        --account-status=1 \
        --account-view-hash=./receiver-view.hash \
        --proof=./sender-auth.proof
FAIL!
$ ../silencer verify --circuit=authorization \
        --verifying-key=./authorization-vk.json \
        --auth-root-hash=./auth-root.hash \
        --account-status=1 \
        --account-view-hash=./sender-view.hash \
        --proof=./receiver-auth.proof
FAIL!
```
