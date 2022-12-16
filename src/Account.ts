import { Field, Struct, Poseidon, UInt64, PublicKey, Bool } from 'snarkyjs';
import { Constant } from './Constant.js';

export class Account extends Struct({
  publicKey: PublicKey,
  token: UInt64,
  isActivated: Bool,
}) {
  constructor(publicKey: PublicKey, token?: UInt64, isActivated?: Bool) {
    super({
      publicKey,
      token: token || UInt64.from(Constant.initialAccountBalance),
      isActivated: isActivated || Bool.not(true),
    });
    this.publicKey = publicKey;
    this.token = token || UInt64.from(Constant.initialAccountBalance);
    this.isActivated = isActivated || Bool.not(true);
  }

  hash(): Field {
    return Poseidon.hash(
      this.publicKey
        .toFields()
        .concat(this.token.toFields().concat(this.isActivated.toField()))
    );
  }
  activate(): Account {
    // console.log("[account] activate()")
    if (this.isActivated.toBoolean()) {
      console.log('account is already activated.');
      return this;
    }
    // return new one.
    // console.log('[account] activating new account...')
    return new Account(this.publicKey, this.token, Bool.not(false));
  }
  balance(): bigint {
    this.isActivated.assertEquals(true);
    return this.token.toBigInt();
  }
  balance_increment(value: number): Account {
    this.isActivated.assertEquals(true);
    this.token.add(value);
    // return new account instance with updated value
    return new Account(this.publicKey, this.token.add(value), this.isActivated);
  }
  balance_decrement(value: number): Account {
    this.isActivated.assertEquals(true);
    // ensure amount > decreasing value
    this.token.assertGte(UInt64.from(value), 'Balance is not enough.');
    this.token.sub(value);
    // return new account instance with updated value
    return new Account(this.publicKey, this.token.sub(value), this.isActivated);
  }
}
