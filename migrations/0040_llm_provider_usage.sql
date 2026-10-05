-- rollback-safe: yes
-- Actual provider charges are separate from the estimated USD cost cap.
-- Nullable for historical rows and callers without provider telemetry.
-- JSON contains only whitelisted metadata (no prompts, answers or balance),
-- with per-attempt decimal-string RUB costs and an explicit completeness flag.
-- An older release ignores this optional column and continues writing rows.
alter table llm_usage add column if not exists provider_usage jsonb;
