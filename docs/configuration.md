# Backend and deployment configuration

Use [`.env.example`](../.env.example) as the backend template. The production
file is `/opt/shipit/.env`; deployments preserve it. The template deliberately
leaves credentials empty and is not a ready-to-start production configuration.
For local development, set `ENVIRONMENT=development` in your local copy.

Keep one assignment per variable and put comments on separate lines. systemd's
`EnvironmentFile` treats inline comments as part of a value. Quote values with
spaces if the file also needs to be read by a shell.

## Required for the shipped production deployment

| Variable | Requirement and purpose |
| --- | --- |
| `ENVIRONMENT` | Set `production` in the env file itself. This selects production validation, release/log labels and the API documentation policy. Local `development` enables interactive API docs. |
| `DATABASE_URL` | PostgreSQL connection URI for persisted audits and the queue. A Supabase HTTPS project URL is not a database URI. Use the Session Pooler URI for the deployed Supabase setup. Without a DB the API can start, but audit intake returns `503 queue_unavailable`. |
| `API_KEY_PEPPER` | Required whenever a DB is configured, even in development: startup refuses a missing pepper. Generate once with `openssl rand -hex 32`; keep the same value across backend processes and releases. Changing it invalidates existing key verification. |
| `PREVIEW_REAP_TOKEN` | Required by the production validator; authorizes the scheduled preview reaper. |
| `FIXPACK_PROCESS_TOKEN` | Required by the production validator; authorizes processing paid Fix Pack jobs. |
| `MONITORING_PROCESS_TOKEN` | Required by the production validator; authorizes the monitoring queue processor. |
| `SERVICE_FLAGS_TOKEN` | Required by the production validator; authorizes the service emergency-stop control. |
| `CORS_ALLOWED_ORIGINS` | Required by the production validator. Comma-separated exact frontend origins, including scheme and without a trailing slash. Empty means no cross-origin browser access. |

Generate each internal token separately with `openssl rand -hex 32`. The
production validator requires these four tokens even when a particular timer
or product feature is not currently used.

## Required when an integration is used

| Integration | Configuration and condition |
| --- | --- |
| AITunnel | Set `AITUNNEL_API_KEY` and `AITUNNEL_BASE_URL` together. With a base URL, production validation also requires `AITUNNEL_LLM_MODEL` or `LLM_MODEL`. Use that provider's model names; configure the preview model separately. Without any configured LLM provider, audits are static-only. |
| Telegram alerts | `TELEGRAM_BOT_TOKEN` and `TELEGRAM_ADMIN_CHAT_ID` enable operator notifications. Outbound alerts alone do not need a webhook secret. |
| Incoming Telegram updates | `TELEGRAM_BOT_TOKEN` and `TELEGRAM_WEBHOOK_SECRET` are required; otherwise the webhook returns 503. The secret must match `secret_token` passed to Telegram `setWebhook`. The operator chat id is separately checked before a payment-confirmation callback can act. |
| Manual bank transfer | Populate all six `BANK_TRANSFER_` bank-detail fields from the template. The runtime treats an incomplete set as unconfigured. Production validation requires the Telegram bot token, operator chat id and webhook secret whenever `BANK_TRANSFER_CARD` or `BANK_TRANSFER_ACCOUNT` is populated. |
| YooKassa card checkout | Set `YOOKASSA_SHOP_ID` and `YOOKASSA_SECRET_KEY` together, or leave both empty. A half-configured pair fails production validation; without the pair card checkout returns 503. A `test_` key is reported as a warning and does not collect real payments. |
| Sandbox runner | Set the same `SANDBOX_RUNNER_TOKEN` in the backend env and `/opt/shipit-runner/.env.runner`. Required for sandbox-backed verification and preview operations. A runner without its token returns 503; a configured runner rejects a missing or mismatched client token with 401. This is an operation requirement, not a check performed by the production env validator. |
| SMTP | Set `SMTP_HOST` and `SMTP_FROM` together. Set both `SMTP_USERNAME` and `SMTP_PASSWORD`, or neither for a relay that needs no credentials. Production validation rejects incomplete pairs. Without the host/from pair, no email is sent. |

The runner has a [separate minimal template](../deploy/sandbox-runner/env.runner.example)
and [installation instructions](../deploy/sandbox-runner/README.md). Share only
the runner token with the backend; do not copy database, account-key, billing or
Telegram credentials into the runner env. Socket access and runner availability
also need to be provisioned and checked separately.

## Optional settings and retired names

- `TELEGRAM_BOT_USERNAME` supplies customer bot links through the backend API.
  Missing it does not disable the bot, but the site cannot offer those links.
- `AUDIT_JOBS_STATS_TOKEN` enables the two internal read-only statistics
  endpoints. Missing it produces a warning, not a startup error.
- `YOOKASSA_VAT_CODE` enables receipt data in payment requests; without it the
  application sends no receipt. `YOOKASSA_TAX_SYSTEM_CODE` is only used with
  receipt data. These are merchant-specific codes with no guessed defaults.
  A missing VAT code is a validator warning, not a startup blocker.
- `BANK_TRANSFER_FIXPACK_PRICE_RUB` overrides the Fix Pack price for bank
  transfer and YooKassa; `BANK_TRANSFER_PRO_PRICE_RUB` applies to the existing
  bank-transfer Pro endpoint. Code defaults are 990.00 and 490.00 RUB
  respectively. Invoices use the exact price without a kopeck suffix; Pro
  remains absent from the storefront.
- PayPal, USDT and Stars sale configuration and the old
  `BANK_TRANSFER_*_PRICE_USD` names are retired. They are removed from the
  template; existing host files need a separate review because deploys preserve
  them. The validator warns about the retired names it recognizes.

Frontend configuration belongs in [`web/.env.example`](../web/.env.example).
`NEXT_PUBLIC_API_BASE_URL` is public. Bot links and payment availability come
from the backend API; private backend credentials never belong in `NEXT_PUBLIC_`
variables.

## Validate the actual service file

```bash
python3 deploy/scripts/validate-production-env.py --env-file /opt/shipit/.env
```

With `--env-file`, the validator reads only that file: shell exports and a
systemd `Environment=ENVIRONMENT=production` setting cannot supply a missing
entry. Without `--env-file`, it validates its process environment. A file with
no `ENVIRONMENT` prints a warning and skips production checks; an explicit
value other than `production` also skips them. Confirm `ENVIRONMENT=production`
in the file before interpreting a successful exit as production validation.

The production file must be readable by the service user (`0640`, owner
`root:shipit-ops`); see [host provisioning](status-active.md#host-provisioning--one-time-not-part-of-a-deploy).
Validation checks configuration shape, not database connectivity, provider
credentials, webhook registration or runner health. Run the existing deployment
health gates and the relevant integration control after configuring a host.
