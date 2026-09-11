-- Drydock metadata snapshot v1. Run in your project's SQL editor as its owner.
-- Replace the project ref below (the part before .supabase.co).
-- This reads catalogs only: no row values, passwords, JWTs or raw policy SQL.
-- Optionally restrict selected_tables; an empty array includes all public tables.
BEGIN READ ONLY;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '1s';

WITH settings AS (
  SELECT 'REPLACE_WITH_PROJECT_REF'::text AS project_ref,
         ARRAY[]::text[] AS selected_tables
), target_roles AS (
  SELECT oid, rolname, rolsuper, rolbypassrls
  FROM pg_catalog.pg_roles WHERE rolname IN ('anon', 'authenticated')
), relations AS (
  SELECT c.*, n.nspname
  FROM pg_catalog.pg_class c
  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
  CROSS JOIN settings s
  WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
    AND (cardinality(s.selected_tables) = 0 OR c.relname = ANY(s.selected_tables))
)
SELECT jsonb_build_object(
  'version', 1,
  'project_ref', (SELECT project_ref FROM settings),
  'captured_at', statement_timestamp(),
  'collector_role', current_user,
  'schema_name', 'public',
  'tables', COALESCE((SELECT jsonb_agg(jsonb_build_object(
    'name', c.relname,
    'object_type', c.relkind,
    'rls_enabled', c.relrowsecurity,
    'rls_forced', c.relforcerowsecurity,
    'collector_rls_applies', pg_catalog.row_security_active(c.oid),
    'columns', COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'name', a.attname,
      'type', pg_catalog.format_type(a.atttypid, a.atttypmod),
      'nullable', NOT a.attnotnull
    ) ORDER BY a.attnum)
      FROM pg_catalog.pg_attribute a
      WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
    ), '[]'::jsonb),
    'privileges', COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'role', r.rolname,
      'schema_usage', pg_catalog.has_schema_privilege(r.oid, c.relnamespace, 'USAGE'),
      'rls_bypassed', r.rolsuper OR r.rolbypassrls OR
        (NOT c.relforcerowsecurity AND pg_catalog.pg_has_role(r.oid, c.relowner, 'USAGE')),
      'select', pg_catalog.has_table_privilege(r.oid, c.oid, 'SELECT'),
      'select_any_column', pg_catalog.has_any_column_privilege(r.oid, c.oid, 'SELECT'),
      'insert', pg_catalog.has_table_privilege(r.oid, c.oid, 'INSERT'),
      'insert_any_column', pg_catalog.has_any_column_privilege(r.oid, c.oid, 'INSERT'),
      'update', pg_catalog.has_table_privilege(r.oid, c.oid, 'UPDATE'),
      'update_any_column', pg_catalog.has_any_column_privilege(r.oid, c.oid, 'UPDATE'),
      'delete', pg_catalog.has_table_privilege(r.oid, c.oid, 'DELETE')
    ) ORDER BY r.rolname) FROM target_roles r), '[]'::jsonb),
    'policies', COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'name', p.polname,
      'command', CASE p.polcmd WHEN '*' THEN 'ALL' WHEN 'r' THEN 'SELECT'
        WHEN 'a' THEN 'INSERT' WHEN 'w' THEN 'UPDATE' WHEN 'd' THEN 'DELETE' END,
      'permissive', p.polpermissive,
      'applies_to', COALESCE((SELECT jsonb_agg(r.rolname ORDER BY r.rolname)
        FROM target_roles r WHERE 0::oid = ANY(p.polroles) OR EXISTS (
          SELECT 1 FROM unnest(p.polroles) policy_role
          WHERE policy_role <> 0::oid AND pg_catalog.pg_has_role(r.oid, policy_role, 'USAGE')
        )), '[]'::jsonb),
      'using', CASE WHEN p.polqual IS NULL THEN NULL
        WHEN pg_catalog.pg_get_expr(p.polqual, p.polrelid) = 'true' THEN 'always'
        WHEN pg_catalog.pg_get_expr(p.polqual, p.polrelid) = 'false' THEN 'never'
        ELSE 'conditional' END,
      'with_check', CASE WHEN p.polwithcheck IS NULL THEN NULL
        WHEN pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) = 'true' THEN 'always'
        WHEN pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) = 'false' THEN 'never'
        ELSE 'conditional' END
    ) ORDER BY p.polname) FROM pg_catalog.pg_policy p WHERE p.polrelid = c.oid), '[]'::jsonb)
  ) ORDER BY c.relname) FROM relations c), '[]'::jsonb)
) AS metadata_snapshot;

COMMIT;
