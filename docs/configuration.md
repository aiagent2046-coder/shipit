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
| AITunnel | Set `AITUNNEL_API_KEY` and `AITUNNEL_BASE_URL` together. With a base URL, production validation also requires `AITUNNEL_LLM_MODEL` or `LLM_MODEL`. Use that provider's model identifiers; configure the preview model separately with `FREE_TIER_LLM_MODEL_AITUNNEL` or `FREE_TIER_LLM_MODEL`. Without any configured LLM provider, audits are static-only. |
| Telegram alerts | `TELEGRAM_BOT_TOKEN` and `TELEGRAM_ADMIN_CHAT_ID` enable operator notifications. Outbound alerts alone do not need a webhook secret. |
| Incoming Telegram updates | `TELEGRAM_BOT_TOKEN` and `TELEGRAM_WEBHOOK_SECRET` are required; otherwise the webhook returns 503. The secret must match `secret_token` passed to Telegram `setWebhook`. The operator chat id is separately checked before a payment-confirmation callback can act. |
| Manual bank transfer | Populate all six `BANK_TRANSFER_` bank-detail fields from the template. The runtime treats an incomplete set as unconfigured. Production validation requires the Telegram bot token, operator chat id and webhook secret whenever `BANK_TRANSFER_CARD` or `BANK_TRANSFER_ACCOUNT` is populated. |
| YooKassa card checkout | Set `YOOKASSA_SHOP_ID` and `YOOKASSA_SECRET_KEY` together, or leave both empty. A half-configured pair fails production validation; without the pair card checkout returns 503. A `test_` key is reported as a warning and does not collect real payments. |
| Sandbox runner | Set the same `SANDBOX_RUNNER_TOKEN` in the backend env and `/opt/shipit-runner/.env.runner`. Required for sandbox-backed verification and preview operations. A runner without its token returns 503; a configured runner rejects a missing or mismatched client token with 401. This is an operation requirement, not a check performed by the production env validator. |
| SMTP | Set `SMTP_HOST` and `SMTP_FROM` together. Set both `SMTP_USERNAME` and `SMTP_PASSWORD`, or neither for a relay that needs no credentials. Production validation rejects incomplete pairs. Without the host/from pair, no email is sent. |

Model identifiers are exact and punctuation can differ by provider. AITunnel's
API examples use [`claude-haiku-4.5`](https://aitunnel.ru/models/claude-haiku-4-5)
and [`claude-sonnet-4.6`](https://aitunnel.ru/models/claude-sonnet-4-6). Copy the
request identifier from the provider's catalog, not the spelling in a page URL.

For an AITunnel preview, a nonblank `FREE_TIER_LLM_MODEL_AITUNNEL` takes
precedence over `FREE_TIER_LLM_MODEL`. When the per-provider override is blank
and the shared variable is absent, the code uses `claude-haiku-4-5`.
The shipped `.env.example` already sets `FREE_TIER_LLM_MODEL=claude-haiku-4.5`;
leaving only the per-provider override blank does not select the code default.
The paid stage reads a nonempty `AITUNNEL_LLM_MODEL` first, falling back to
`LLM_MODEL`; neither variable selects the preview model. An unsupported
identifier can cause the provider's LLM request to fail; if no configured
fallback succeeds, the pipeline records that failure and retains static
findings. This does not imply that Drydock's own preview endpoint returns
HTTP 400.

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
/srv/shipit/current/.venv/bin/python scripts/verify_llm_provider.py --env /opt/shipit/.env
```

Run these from the release directory (`/srv/shipit/current` on the standard
host); for a local checkout use its `.venv/bin/python` instead. The validator
checks configuration shape. The provider check uses only the selected file,
with the same quote parsing; shell exports cannot fill missing values or
replace its models/keys. `--process-env` explicitly selects exported settings
instead, and cannot be combined with `--env`.

The provider check prints the fallback chain and both paid/preview model names,
then checks each provider's authenticated model catalog. It uses the provider's
own protocol, including [Anthropic pagination](https://platform.claude.com/docs/en/api/models/list).
For AITunnel, the authenticated `/v1/models` endpoint is distinct from its
[public model/pricing catalog](https://aitunnel.ru/docs/models). An identifier
missing from a catalog is reported as unconfirmed; this alone does not prove
that a completion request would return HTTP 400. Anthropic aliases absent from
its listing are additionally checked with the official
[get-model endpoint](https://platform.claude.com/docs/en/api/models/retrieve);
other providers' unlisted aliases remain unconfirmed. Catalog success does not
test generation, balance or audit quality.

Generation is a separate, **potentially billed** opt-in:

```bash
/srv/shipit/current/.venv/bin/python scripts/verify_llm_provider.py --env /opt/shipit/.env --probe
```

Each catalog-confirmed provider/model gets one attempt through `LLMClient`'s
actual payload and nonempty-answer parser, without automatic retries or fallback.
The request sets `max_tokens=8`, but this is **not a guarantee of eight billed
tokens or a spending cap**. The report shows returned token counts and served
model, without response text, keys or raw exception messages. A short successful
probe does not verify the full audit prompt, context window or billing estimate.

Exit codes: `0` means all requested checks passed; `1` means invalid/unconfigured
settings, an unlisted model or an invalid completion; `2` means verification was
incomplete due to network, auth, HTTP or catalog errors. If both kinds occur,
`2` takes precedence and the report retains both failures. Run the catalog check
after changing provider credentials/URLs, `LLM_MODEL`, per-provider paid models
or `FREE_TIER_LLM_MODEL*` settings.

Unknown models such as `grok-4.20-multi-agent` currently use `DEFAULT_PRICE`
($3 input / $15 output per million tokens) for internal USD estimates. Those
rates are the maximum among known table entries, **not a verified upper bound**
on an unknown model's bill. The estimate can be too high or too low; the audit
cap is checked after each response and can stop subsequent calls. The default
200,000-token input budget is also a local heuristic, not a verified context
window for Grok. Neither catalog checks nor a small probe establishes these
limits. Verify provider billing and representative audit behaviour before
relying on them for a model switch.

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
