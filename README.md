# Mina zkApp: 06-zkLedger

An attempt to build on-chain && off-chain Ledger to secure wallets with a single MINA account.

## How it work

1. You activate your account on zkApp with a password, which will be later used for encryption.
- zkLedger return new proofs of the activation, then make proofs of the whole off-chain ledger to submit on-chain. 

2. You set new wallet/account mnemonic on zkApp by bip39 keyword set, with your password & last login proofs.
- zkLedger will verify `your latest proofs` along with `your password` to allow the secret key to be modified everytime.
- It will return new proofs to you after encrypted your mnemonic into off-chain ledger, and submit new ledger proofs.

3. To reveal the secret/keys: use your proofs (again) with password to access it.
- zkLedger again, will verify [proofs + password] to decrypt the key and send ya. This function could be just replaced with signing Txs in real usecase.

## Note 

1. I haven't added this, but everytime user make new action, his secret could be just re-encrypted again with old proofs, which improve the security further to prevent revealed proofs to be used to attack. So even when the password is revealed, if hacker don't have the proofs, he still can't access the keys.

2. By the way it work, it is nothing different from your mobile wallet, and so the security really depends on the host environment since smart contract and encryption arn executed off-chain, even data is just off-chain storage. Unlike the 'real ledger' that has its own isolated environment to execute Txs. On the pros, you may safely backup your keys on-chain, where off-chain storage is safe to use ( although hard to say if it's safe anywhere online ).

## How to build

```sh
npm run build
```

## How to build & run

```sh
npm run build && node build/src/main.js
```


## How to run tests

```sh
npm run test
npm run testw # watch mode
```

## How to run coverage

```sh
npm run coverage
```

## License

[Apache-2.0](LICENSE)
