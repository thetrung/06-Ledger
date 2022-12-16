import {
  SmartContract,
  state,
  State,
  Field,
  method,
  UInt64,
  DeployArgs,
  Permissions,
} from 'snarkyjs';

import { Account } from './Account.js';
import { Constant } from './Constant.js';
import { NthMerkleWitness } from './NthMerkleWitness.js';

export class Ledger extends SmartContract {
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
    this.balance.addInPlace(UInt64.from(Constant.initialPayerBalance));
  }

  @method updateProofs(commitment: Field) {
    // console.log('[Ledger] updateProofs()')
    // fetch commitment
    let lastest = this.commitment.get();
    this.commitment.assertEquals(lastest);

    // update new commitment
    this.commitment.set(commitment);
  }

  @method activate(account: Account, root: Field, witness: NthMerkleWitness) {
    // console.log('[Ledger] activateAccount()')
    // fetch commitment
    let commitment = this.commitment.get();
    this.commitment.assertEquals(commitment);
    // check if account is within our committed merkle tree
    root.assertEquals(
      commitment,
      'Failed to activate account due to unmatched root.'
    );
    // activate account :
    let updatedAccount = account.activate();
    let newCommitment = witness.calculateRoot(updatedAccount.hash());

    this.commitment.set(newCommitment);
  }
}
