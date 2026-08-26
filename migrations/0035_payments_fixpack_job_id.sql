-- rollback-safe: yes
--
-- A nullable column nothing older reads or writes. A release rolled back to the
-- previous code ignores it, and every existing row stays valid.
--
-- Which Fix Pack job this order paid for.
--
-- WHY audit_id IS NOT ENOUGH, which is the whole reason this column exists.
-- One audit can carry SEVERAL Fix Pack jobs and several orders. Migration
-- 0025's partial unique index allows only one LIVE job per audit, so re-buying
-- is refused while one is running -- but once a job reaches a terminal status,
-- create_paid deliberately inserts a fresh row, because re-buying after a
-- delivered or failed Fix Pack is a supported flow. Nothing then distinguishes
-- the orders from each other except time.
--
-- On 2026-08-25 audit 2031a34d ended the day with four jobs (two delivered,
-- two no_fix_needed) and five orders. The code that tells a buyer their Fix
-- Pack found nothing to change looked its payer up by audit and took the
-- newest, which would have written to the same person twice and to the other
-- buyer not at all -- and paged the operator twice with one order number,
-- leaving the second refund unsent. A message reaching the wrong person is the
-- defect this whole week has been about; this column is the fact that prevents
-- it, rather than another heuristic on top of the same ambiguity.
--
-- ON payments RATHER THAN ON fixpack_jobs, and that is not arbitrary.
-- grant_fixpack creates the job BEFORE it writes the payment, in both of its
-- branches, so the job id is in hand at the moment the payment row is written:
-- the link goes in with the INSERT that creates the payment or the UPDATE that
-- completes it. The other direction would need a third write after both, and a
-- third write is a third place a crash can leave the pair half-linked.
--
-- Not unique. A payment points at exactly one job, but nothing here needs to
-- forbid two payments pointing at one job -- a duplicate charge reconciled by
-- hand is a bookkeeping event, not a constraint violation, and a unique index
-- would turn it into a 500 during the reconciliation.
alter table payments add column if not exists fixpack_job_id uuid
    references fixpack_jobs(id);

create index if not exists payments_fixpack_job_id_idx
    on payments (fixpack_job_id)
    where fixpack_job_id is not null;

-- Backfill ONLY where the pairing is a fact.
--
-- An audit holding exactly one Fix Pack job and exactly one Fix Pack order has
-- one possible answer, and leaving those rows null would mean the fix does not
-- work for anything bought before today. An audit holding more of either has
-- several possible answers, and the tempting one -- pair them off by
-- created_at -- is a guess that reads like a fact once it is written down. The
-- rows it would fill are exactly the rows where being wrong misdirects a
-- refund, so they stay null and the code refuses to guess about them.
--
-- Counts ignore payment status on purpose: a pending order sitting next to a
-- completed one is still a second order against that audit, and this is the
-- conservative direction.
with unambiguous as (
    select p.id as payment_id, j.id as job_id
    from payments p
    join fixpack_jobs j on j.audit_id = p.audit_id
    where p.product = 'fixpack'
      and p.audit_id is not null
      and (select count(*) from fixpack_jobs j2
           where j2.audit_id = p.audit_id) = 1
      and (select count(*) from payments p2
           where p2.audit_id = p.audit_id and p2.product = 'fixpack') = 1
)
update payments
   set fixpack_job_id = unambiguous.job_id
  from unambiguous
 where payments.id = unambiguous.payment_id;
