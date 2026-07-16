-- Fix Pack purchase: a second product, sold per-audit, separate from the
-- Pro tier. Two additions to `payments` plus one status flag on
-- `fixpack_jobs`, all backward-compatible with the existing Pro-tier flow.
--
-- product: which thing this payment buys. 'pro_tier' (raises the daily
-- audit limit, the only product until now) or 'fixpack' (a generated fix
-- PR for one specific audit). Plain text with a default, same reasoning
-- as `provider`/`status`/`tier_granted` in 0003: no enum/check constraint
-- that would need its own migration when a third product appears. The
-- default 'pro_tier' means every existing row -- and any Pro-tier code
-- path that doesn't yet set it -- keeps its current meaning unchanged.
alter table payments add column if not exists product text not null default 'pro_tier';

-- audit_id: which audit a fixpack payment is for. Null for pro_tier
-- payments (a tier is account-wide, not tied to one audit) -- same "null
-- is the common, legitimate case" reasoning as external_ref on a pending
-- invoice. FK to audits so a fixpack payment can't reference a
-- nonexistent audit.
alter table payments add column if not exists audit_id uuid references audits(id);

create index if not exists payments_audit_id_idx on payments (audit_id)
    where audit_id is not null;

-- fixpack_jobs.status: distinguish a purchased-but-not-yet-generated
-- fixpack from the rows the Deploy Pack flow writes after it has already
-- built (and maybe verified) a pack. The existing flow never set a status
-- and its rows represent an already-generated pack, so the default is
-- 'generated'; a Fix Pack purchase inserts a row with status 'paid' that
-- the (separate, follow-up) generation step will later pick up and
-- advance. Plain text + default, same rationale as `product` above.
alter table fixpack_jobs add column if not exists status text not null default 'generated';
