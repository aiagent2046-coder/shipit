/**
 * The support address, as a link.
 *
 * Exists because four post-payment recovery messages told the buyer to
 * "contact the operator" or "contact support" without an address anywhere on
 * the page — the Fix Pack failure branches, a USDT payment whose key was
 * lost, a PayPal order that didn't save, and a confirmed Pro transfer. Two of
 * those channels have since been removed; the moment they described has not.
 * It is when a stranger has already paid and has nothing, which is exactly
 * when a dead end turns a refund conversation into an accusation of fraud.
 *
 * Deliberately just the link: each caller keeps its own sentence and its own
 * identifier (reference, payer name and amount), because what the operator
 * needs to match on differs per payment channel.
 *
 * The six older hand-written copies of this address are left alone. They work,
 * and replacing them is a refactor this change does not need.
 */
export function SupportEmail() {
  return (
    <a
      href="mailto:support@drydock.co"
      className="underline underline-offset-2"
    >
      support@drydock.co
    </a>
  );
}
