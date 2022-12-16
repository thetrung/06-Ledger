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
  Field,
  CircuitString,
} from 'snarkyjs';

import { generate_mnemonic } from 'tezallet';

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
  'initial off-chain proofs :\n%s\n',
  initialOffChainProofs.toString().slice(0, 16)
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
console.log('root: %s\n', zkLedger.commitment.get().toString().slice(0, 16));

async function updateOffChainAccount(
  name: string,
  updatedAccount: Account,
  index: bigint,
  funcName: string
) {
  // fetch latest :
  const latestCommit = zkLedger.commitment.get();
  console.log('proofs: %s', latestCommit.toString().slice(0, 16));

  // update to off-chain ledger
  const updatedAccountHash = updatedAccount.hash();
  Accounts.set(name, updatedAccount); // Map
  Tree.setLeaf(index, updatedAccountHash); // MerkleTree
  // verify off-chain commitment :
  latestCommit.assertEquals(
    Tree.getRoot(),
    funcName + ' unmatched root after activated new account.'
  );
}

async function activateAccount(
  name: Names,
  index: bigint,
  password: string
): Promise<Field> {
  // Test activate ()
  const is_activated = Accounts.get(name)?.isActivated.toBoolean();
  console.log('\n%s account is activated: ', name, is_activated);

  if (is_activated) return Field(0);
  // fetch account
  const account = Accounts.get(name)!;
  // witness & root
  const witness = new NthMerkleWitness(Tree.getWitness(index));
  const root = witness.calculateRoot(account.hash());
  console.log('root: %s', root.toString().slice(0, 16));
  // password
  const fieldPassword = CircuitString.fromString(password);
  // TX: activate()
  const tx = await Mina.transaction(feePayer, () => {
    zkLedger.activate(account, root, witness, fieldPassword);
    if (!doProofs) zkLedger.sign(zkAppPrivatekey);
  });
  if (doProofs) await tx.prove();
  await tx.send();
  // update to off-chain ledger
  const updatedAccount = account.activate(fieldPassword);
  updateOffChainAccount(name, updatedAccount, index, 'activateAccount');

  // log
  console.log(
    '%s account is activated: ',
    name,
    updatedAccount.isActivated.toBoolean()
  );

  return updatedAccount.hash();
}

// Try Bob
var bob_proofs = await activateAccount('Bob', 0n, 'password123');
// await activateAccount('Alice', 1n, 'password')
// await activateAccount('Olivia', 2n, 'password')
// await activateAccount('Charlie', 3n, 'password')

async function setKey(
  name: Names,
  index: bigint,
  proofs: Field,
  password: string,
  newKey: string
): Promise<Field> {
  // start !
  console.log('\n[setKey] init for %s', name);
  // get account
  const account = Accounts.get(name)!;
  console.log('old key: %s', account.mnemonic.toString().slice(0, 16));
  // is_activated?
  const is_activated = account.isActivated.toBoolean();
  if (!is_activated) {
    console.log(
      '\n[setKey] %s account is (not) activated :',
      name,
      is_activated
    );
    return Field(0);
  }
  // witness & root
  const witness = new NthMerkleWitness(Tree.getWitness(index));
  const root = witness.calculateRoot(account.hash());
  console.log('root: %s', root.toString().slice(0, 16));
  const fieldPassword = CircuitString.fromString(password);
  const fieldNewKey = CircuitString.fromString(newKey);
  // TX: setKey
  const tx = await Mina.transaction(feePayer, () => {
    zkLedger.setKey(account, root, witness, proofs, fieldPassword, fieldNewKey);
    if (!doProofs) zkLedger.sign(zkAppPrivatekey);
  });
  if (doProofs) await tx.prove();
  await tx.send();
  // update to off-chain instance
  const updatedAccount = account.setKey(fieldNewKey, fieldPassword, proofs);
  updateOffChainAccount(name, updatedAccount, index, 'setKey');
  // log hash
  console.log('new key: %s', updatedAccount.mnemonic.toString().slice(0, 16));
  // return for testing
  return updatedAccount.hash();
}

const sample_mnemonic = generate_mnemonic();
bob_proofs = await setKey(
  'Bob',
  0n,
  bob_proofs,
  'password123',
  sample_mnemonic
);

async function revealKey(
  name: Names,
  index: bigint,
  proofs: Field,
  password: string
): Promise<string> {
  // start !
  console.log('\n[revealKey] init for %s', name);
  // get account
  const account = Accounts.get(name)!;
  // is_activated?
  const is_activated = account.isActivated.toBoolean();
  if (!is_activated) {
    console.log(
      '\n[revealKey] %s account is (not) activated :',
      name,
      is_activated
    );
    throw 'nothing.';
  }
  // compare proofs && root
  proofs.assertEquals(account.hash(), 'wrong proofs.');
  // reveal key
  const fieldPassword = CircuitString.fromString(password);
  const decrypted = account.revealKey(fieldPassword, proofs);
  return decrypted;
}

// test Bob again
const revealedKey = await revealKey('Bob', 0n, bob_proofs, 'password123');
console.log('revealed key: ', revealedKey);

// shutdown MINA
await shutdown();
