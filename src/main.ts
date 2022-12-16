/// This was based on O(1) Lab sample of Leaderboard at :
/// https://github.com/o1-labs/snarkyjs/blob/main/src/examples/zkapps/merkle_tree/merkle_zkapp.ts
///
/// Similar mechanism but extending as a on-chain/off-chain Ledger,
/// that let user use only MINA account to access all added keys.
///
/// TODO:
/// - Implement Add/Remove/Get methods to access encrypted ledger.
///
import {
  MerkleTree,
  Mina,
  isReady,
  shutdown,
  PrivateKey,
  AccountUpdate,
} from 'snarkyjs';

await isReady;
console.log('SnarkyJS loaded.');
// Wait till SnarkyJS is loaded before anything else.

import { Ledger } from './Ledger.js';
import { Account } from './Account.js';
import { Constant } from './Constant.js';
import { NthMerkleWitness } from './NthMerkleWitness.js';

let doProofs = false; //true

type Names = 'Bob' | 'Alice' | 'Olivia' | 'Charlie';

let Local = Mina.LocalBlockchain();
Mina.setActiveInstance(Local);

let feePayer = Local.testAccounts[0].privateKey;

// zkApp setup
let zkAppPrivatekey = PrivateKey.random();
let zkAppAddress = zkAppPrivatekey.toPublicKey();
console.log('finished environment setup.');

// off-chain Ledger
let Accounts: Map<String, Account> = new Map<Names, Account>();

let bob = new Account(Local.testAccounts[1].publicKey);
let alice = new Account(Local.testAccounts[2].publicKey);
let olivia = new Account(Local.testAccounts[3].publicKey);
let charlie = new Account(Local.testAccounts[4].publicKey);

Accounts.set('Bob', bob);
Accounts.set('Alice', alice);
Accounts.set('Olivia', olivia);
Accounts.set('Charlie', charlie);

// Merkle Tree -> Root -> Commitment proofs
const Tree = new MerkleTree(8);
Tree.setLeaf(0n, bob.hash());
Tree.setLeaf(1n, alice.hash());
Tree.setLeaf(2n, olivia.hash());
Tree.setLeaf(3n, charlie.hash());

// get commitment for smart contract
const initialOffChainProofs = Tree.getRoot();
console.log(
  'initial off-chain ledger proofs :\n%s\n',
  initialOffChainProofs.toString()
);

let zkLedger = new Ledger(zkAppAddress);
if (doProofs) {
  await Ledger.compile();
  console.log('\nCompiled Ledger.');
}

const tx_deploy = await Mina.transaction(feePayer, () => {
  AccountUpdate.fundNewAccount(feePayer, {
    initialBalance: Constant.initialPayerBalance,
  });
  zkLedger.deploy({ zkappKey: zkAppPrivatekey });
});
await tx_deploy.send();
console.log('Ledger deployed.\n');

/** Start digging into proofs **/

const tx_initProofs = await Mina.transaction(feePayer, () => {
  zkLedger.updateProofs(initialOffChainProofs);
  if (!doProofs) zkLedger.sign(zkAppPrivatekey);
});
if (doProofs) await tx_initProofs.prove();
await tx_initProofs.send();
console.log('[Ledger] updated latest proofs.');
console.log('root: %s\n', zkLedger.commitment.get().toString());

async function activateAccount(name: Names, index: bigint) {
  // Test activate ()
  const is_activated = Accounts.get(name)?.isActivated.toBoolean();
  console.log('\n%s account is activated: ', name, is_activated);

  if (is_activated) return;

  const account = Accounts.get(name)!;
  const w = Tree.getWitness(index);
  const witness = new NthMerkleWitness(w);
  const root = witness.calculateRoot(account.hash());
  console.log('root: %s', root.toString().slice(0, 16));

  const tx = await Mina.transaction(feePayer, () => {
    zkLedger.activate(account, root, witness);
    // if no proofs then sign & send
    if (!doProofs) zkLedger.sign(zkAppPrivatekey);
  });
  // if do proofs then prove tx before sending :
  if (doProofs) await tx.prove();
  await tx.send();
  // fetch latest :
  const latestCommit = zkLedger.commitment.get();
  // logs :
  console.log('proofs: %s', latestCommit.toString().slice(0, 16));

  // update to off-chain ledger
  const updatedAccount = account.activate();
  // update our map
  Accounts.set(name, updatedAccount);
  // update our tree wrap
  Tree.setLeaf(index, updatedAccount.hash());
  // check if it matched our latest commitment
  latestCommit.assertEquals(
    Tree.getRoot(),
    '[activateAccount] unmatched root after activated new account.'
  );
  // log
  console.log(
    '%s account is activated: ',
    name,
    updatedAccount.isActivated.toBoolean()
  );
}

// Try Bob
await activateAccount('Bob', 0n);
await activateAccount('Alice', 1n);
await activateAccount('Olivia', 2n);
await activateAccount('Charlie', 3n);

await shutdown();
