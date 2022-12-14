/// This was based on O(1) Lab sample of Leaderboard at :
/// https://github.com/o1-labs/snarkyjs/blob/main/src/examples/zkapps/merkle_tree/merkle_zkapp.ts
///
/// Similar mechanism but extending as a Token Ledger.
/// TODO:
/// - Implement as ERC20 model.
///
import {
  SmartContract,
  state,
  State,
  Field,
  Struct,
  Poseidon,
  method,
  UInt64,
  MerkleTree,
  MerkleWitness,
  Mina,
  isReady,
  shutdown,
  PublicKey,
  PrivateKey,
  DeployArgs,
  Permissions,
  AccountUpdate,
  Bool,
} from 'snarkyjs';

await isReady;
console.log('SnarkyJS loaded.');

let doProofs = false; //true;

// initial balance ?
let initialPayerBalance = 1_000_000_000;
const initialAccountBalance = UInt64.from(0); // zero

class MyMerkleWitness extends MerkleWitness(8) {}

class Account extends Struct({
  publicKey: PublicKey,
  token: UInt64,
  isActivated: Bool,
}) {
  constructor(publicKey: PublicKey) {
    super({
      publicKey,
      token: initialAccountBalance,
      isActivated: Bool.not(true),
    });
    this.token = initialAccountBalance;
    this.publicKey = publicKey;
  }

  hash(): Field {
    return Poseidon.hash(
      this.publicKey
        .toFields()
        .concat(this.token.toFields().concat(this.isActivated.toField()))
    );
  }
  activate(): Account {
    // this.isActivated.assertFalse();
    this.isActivated = Bool.not(false);
    return this;
  }
  balance(): bigint {
    this.isActivated.assertEquals(true);
    return this.token.toBigInt();
  }
  balance_increment(value: number): Account {
    this.isActivated.assertEquals(true);
    this.token.add(value);
    return this;
  }
  balance_decrement(value: number): Account {
    this.isActivated.assertEquals(true);
    // ensure amount > decreasing value
    this.token.assertGte(UInt64.from(value), 'Balance is not enough.');
    this.token.sub(value);
    return this;
  }
}

class Ledger extends SmartContract {
  // a commitment is a cryptographic primitive allow us to commit data,
  // but can be revealed later.
  @state(Field) commitment = State<Field>();

  deploy(args: DeployArgs) {
    super.deploy(args);
    this.setPermissions({
      ...Permissions.default(),
      editState: Permissions.proofOrSignature(),
    });
    // initial empty tree root
    this.commitment.set(Field(0));
    this.balance.addInPlace(UInt64.from(initialPayerBalance));
  }

  @method updateProofs(commitment: Field) {
    // fetch commitment
    let lastCommitment = this.commitment.get();
    this.commitment.assertEquals(lastCommitment);

    // update new commitment
    this.commitment.set(commitment);
  }

  @method activateAccount(
    account: Account,
    root: Field,
    witness: MyMerkleWitness
  ) {
    // fetch commitment
    let commitment = this.commitment.get();
    this.commitment.assertEquals(commitment);
    // check if account is within our committed merkle tree
    root.assertEquals(
      commitment,
      'Failed to activate account due to unmatched root.'
    );

    let updatedAccount = account.activate();

    let newCommitment = witness.calculateRoot(updatedAccount.hash());

    this.commitment.set(newCommitment);
  }
}

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

// Wrap Merkle Tree around off-chain map
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
    initialBalance: initialPayerBalance,
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

async function activate(name: Names, index: bigint) {
  // Test activate ()
  const is_activated = Accounts.get(name)?.isActivated;
  console.log('\n%s account is activated: ', name, is_activated?.toBoolean());
  is_activated?.assertFalse();

  const account = Accounts.get(name)!;
  const w = Tree.getWitness(index);
  const witness = new MyMerkleWitness(w);
  const root = witness.calculateRoot(account.hash());
  console.log('root: %s', root);

  const tx = await Mina.transaction(feePayer, () => {
    zkLedger.activateAccount(account, root, witness);
    // if no proofs then sign & send
    if (!doProofs) zkLedger.sign(zkAppPrivatekey);
  });
  // if do proofs then prove tx before sending :
  if (doProofs) await tx.prove();
  await tx.send();
  // fetch latest :
  const latestCommit = zkLedger.commitment.get();
  // logs :
  console.log('proofs: %s', latestCommit.toString());

  // update to off-chain ledger
  const updatedAccount = account.activate();
  Tree.setLeaf(index, updatedAccount.hash());
  latestCommit.assertEquals(Tree.getRoot());
  console.log(
    '%s account is activated: ',
    name,
    account.isActivated.toBoolean()
  );
  // console.log("updated off-chain ledger.");
}

// Try Bob
await activate('Bob', 0n);
await activate('Alice', 1n);
await activate('Olivia', 2n);
await activate('Charlie', 3n);

await shutdown();
