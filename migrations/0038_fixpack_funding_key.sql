-- rollback-safe: yes
-- Older releases ignore the nullable column. Do not infer funding for old jobs:
-- several confirmed payments may already point to the same job.
alter table fixpack_jobs add column if not exists funding_key text;
create unique index if not exists fixpack_jobs_funding_key_idx
    on fixpack_jobs (funding_key) where funding_key is not null;
