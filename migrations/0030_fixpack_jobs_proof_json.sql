-- Proof-of-Exploit → Proof-of-Fix report storage on fixpack_jobs.
--
-- Structured before/after exploit results for the informational proof
-- stage. NULL means proof was never run (existing rows, unsupported
-- findings, or templates that skipped). No NOT NULL, no enum — same
-- posture as every other status/json column in this project.
--
-- Heavy artifacts (full logs, future GIF/video) stay out of this column
-- and will go to object storage when they exist. This holds the small
-- decision record used for PR markdown and later (optional) gating.

alter table fixpack_jobs
  add column if not exists proof_json jsonb;
