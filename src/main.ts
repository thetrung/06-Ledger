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

// IPFS
// import * as IPFS from 'ipfs-core';

import { encrypt_mnemonic, generate_mnemonic, encrypt_data } from 'tezallet';

await isReady;
console.log('SnarkyJS loaded.');
// Wait till SnarkyJS is loaded before anything else.

import { Ledger } from './Ledger.js';
import { Account } from './Account.js';
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

/* new data type :
 *
 *
 * AccountStorage :
 * secret_1 * encrypted([12]ids)
 *
 * Segments :
 * ids * encrypted(public_ipfs_address)
 */

const shortenHash = (str: string, amount = 4): string => {
  const length = str.length;
  return str
    .slice(0, amount)
    .concat('...')
    .concat(str.slice(length - amount, length));
};

// get commitment for smart contract
const initialOffChainProofs = Tree.getRoot();
console.log(
  'initial off-chain proofs :\n%s\n',
  shortenHash(initialOffChainProofs.toString())
);

let zkLedger = new Ledger(zkAppAddress);
if (doProofs) {
  await Ledger.compile();
  console.log('\nCompiled Ledger.');
}

const tx_deploy = await Mina.transaction(feePayer, () => {
  AccountUpdate.fundNewAccount(feePayer);
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
console.log('root: %s\n', shortenHash(zkLedger.commitment.get().toString()));

async function updateOffChainAccount(
  name: string,
  updatedAccount: Account,
  index: bigint,
  funcName: string
) {
  // fetch latest :
  const latestCommit = zkLedger.commitment.get();
  console.log('account proofs: %s', shortenHash(latestCommit.toString()));

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
  // password
  const fieldPassword = account.encrypt(CircuitString.fromString(password));
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
  console.log('\n[setKey] for %s', name);
  // get account
  const account = Accounts.get(name)!;

  // witness & root
  const witness = new NthMerkleWitness(Tree.getWitness(index));
  const root = witness.calculateRoot(account.hash());
  console.log('root: %s', shortenHash(root.toString()));
  console.log(newKey.toString());
  // length limitation ?
  // if (newKey.toString().length > 128) throw '128 characters or less.';
  // encrypt 1-way password
  const fieldPassword = account.encrypt(CircuitString.fromString(password));
  // verify password + proofs
  account.verify(fieldPassword, proofs);
  // encrypt new key
  const encryptedNewKey = encrypt_mnemonic(
    newKey.toString(),
    fieldPassword.toString(),
    account.v_buffer()
  );
  // log hash
  const str = encryptedNewKey.toString();
  console.log('[newKey](%d Bytes)', str.length, str);

  console.log('\n');
  const SEGMENT_AMOUNT = 12;
  const size = str.length / SEGMENT_AMOUNT;
  for (let i = 0; i < SEGMENT_AMOUNT; i++) {
    const slice = str.slice(i * size, (i + 1) * size);
    const encrypted_slice = encrypt_data(
      slice,
      fieldPassword.toString(),
      account.v_buffer()
    );
    console.log('%d.%s => %s', i + 1, slice, encrypted_slice);
  }

  // export
  const fieldNewKey = CircuitString.fromString(encryptedNewKey);

  // TX: setKey
  const tx = await Mina.transaction(feePayer, () => {
    zkLedger.setKey(account, root, witness, fieldPassword, fieldNewKey);
    if (!doProofs) zkLedger.sign(zkAppPrivatekey);
  });
  if (doProofs) await tx.prove();
  await tx.send();

  // update to off-chain instance
  const updatedAccount = account.setKey(fieldNewKey, fieldPassword);
  updateOffChainAccount(name, updatedAccount, index, 'setKey');

  // return for testing
  return updatedAccount.hash();
}

bob_proofs = await setKey(
  'Bob',
  0n,
  bob_proofs,
  'password123',
  generate_mnemonic(128) // 128 = 12 words
);
// bob_proofs = await setKey(
//   'Bob',
//   0n,
//   bob_proofs,
//   'password123',
//   generate_mnemonic()
// );

async function revealKey(
  name: Names,
  index: bigint,
  proofs: Field,
  password: string
): Promise<string> {
  // start !
  console.log('\n[revealKey] for %s', name);
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
  const encryptedPassword = account.encrypt(fieldPassword);
  account.verify(encryptedPassword, proofs);
  const decrypted = account.revealKey(fieldPassword);
  return decrypted;
}

// test Bob again
const revealedKey = await revealKey('Bob', 0n, bob_proofs, 'password123');
console.log('decrypted: ', revealedKey);

// shutdown MINA
await shutdown();
