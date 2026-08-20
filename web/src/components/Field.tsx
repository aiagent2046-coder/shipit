/**
 * One read-only labelled row, optionally copyable.
 *
 * Lived in UsdtCheckout.tsx, because that is where the first invoice detail
 * needed rendering. BankTransferCheckout imported it from there, so when USDT
 * was removed as a way to pay, deleting that file would have taken the layout
 * of the checkout that survived. It is not a USDT thing and never was.
 *
 * The editable twin is BankTransferCheckout's own `EditableField`, which keeps
 * the same bordered row and muted label so a form and a receipt read as one
 * surface.
 */
export function Field({
  label,
  value,
  mono,
  breakAll,
  onCopy,
  copied,
}: {
  label: string;
  value: string;
  mono?: boolean;
  breakAll?: boolean;
  onCopy?: () => void;
  copied?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-border bg-surface px-3 py-2 text-sm">
      <span className="shrink-0 text-muted">{label}</span>
      <span
        className={`text-right ${mono ? "font-mono" : ""} ${
          breakAll ? "break-all" : ""
        }`}
      >
        {value}
      </span>
      {onCopy && (
        <button
          type="button"
          onClick={onCopy}
          className="shrink-0 rounded border border-border px-2 py-0.5 text-xs text-muted hover:text-text"
        >
          {copied ? "✓" : "Copy"}
        </button>
      )}
    </div>
  );
}
