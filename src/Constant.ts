// initial balance ?
const initialPayerBalance = 1_000_000_000;
// initial
const initialAccountBalance = 0; // zero

export class Constant {
  static get initialPayerBalance() {
    return initialPayerBalance;
  }
  static get initialAccountBalance() {
    return initialAccountBalance;
  }
}
