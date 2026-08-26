# Payment rail (current)

**Primary card rail: ЮKassa** (`app/billing/yookassa.py`, `app/routes/yookassa.py`).

- Webhook notifications are **hints only** — status, amount, and currency are
  confirmed via authenticated `GET /v3/payments/{id}` with our credentials.
- Storefront pay button opens a ЮKassa-hosted checkout (no card data on our origin).
- Bank transfer (`app/billing/bank_transfer.py`) remains the manual-oracle path.
- Robokassa / enot.io are **not** the production rail (historical docs may still mention them).

Customer notifications: `app/notify/` (email + Telegram) with channel selfcheck
(`python -m app.notify.selfcheck` / `shipit-notify-check.timer`).
