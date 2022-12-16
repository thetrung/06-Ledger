import {
  SmartContract,
  state,
  State,
  Field,
  method,
  UInt64,
  DeployArgs,
  Permissions,
  CircuitString,
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

  /**
   * Update proofs on-chain with new commitment.
   * @param commitment the hash proofs from off-chain ledger.
   */
  @method updateProofs(commitment: Field) {
    // fetch commitment
    let lastest = this.commitment.get();
    this.commitment.assertEquals(lastest);

    // update new commitment
    this.commitment.set(commitment);
  }

  /**
   * Activate an account by setting up new password.
   * @param account to be activated.
   * @param proofs current proofs to verify.
   * @param witness witness
   * @param newPassword setup new account password
   */
  @method activate(
    account: Account,
    proofs: Field,
    witness: NthMerkleWitness,
    newPassword: CircuitString
  ) {
    // fetch commitment
    const commitment = this.commitment.get();
    this.commitment.assertEquals(commitment);
    // check if account is within our committed merkle tree
    proofs.assertEquals(commitment, 'Unmatched proofs to activate account.');
    // activate account :
    // console.log('[Ledger/activate]')
    const updatedAccount = account.activate(newPassword);
    const newCommitment = witness.calculateRoot(updatedAccount.hash());
    // commit change :
    this.commitment.set(newCommitment);
  }

  /**
   * Set Key for account with :
   * @param account target account to modify
   * @param root check commitment proofs
   * @param proofs old key hash
   * @param password account password
   * @param newKey new key to set
   */
  @method setKey(
    account: Account,
    root: Field,
    witness: NthMerkleWitness,
    proofs: Field,
    password: CircuitString,
    newKey: CircuitString
  ) {
    // fetch commitment
    let commitment = this.commitment.get();
    this.commitment.assertEquals(commitment);
    // check if account is within our committed merkle tree
    root.assertEquals(commitment, 'Unmatched proofs to set new key.');
    // set account new key :
    const updatedAccount = account.setKey(newKey, password, proofs);
    const newCommitment = witness.calculateRoot(updatedAccount.hash());
    // commit change :
    this.commitment.set(newCommitment);
  }
}
