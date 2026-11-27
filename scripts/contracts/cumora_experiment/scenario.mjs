import { createHash, randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import pg from 'pg';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const evidence = {
  schema_version: 1,
  scenario_sha256: createHash('sha256').update(readFileSync(fileURLToPath(import.meta.url))).digest('hex'),
  scenario_id: 'cumora-project-tenant-isolation-v1',
  run_id: process.env.CONTROL_RUN_ID ?? '',
  archive_sha256: process.env.CONTROL_ARCHIVE_SHA256 ?? '',
  scope: 'client_application_runtime',
  status: 'failed',
  started_at: new Date().toISOString(),
  authentication: 'dedicated_database_seeded_sessions',
  vulnerabilityRemediationVerified: false,
  oauthVerified: false,
  wholeApplicationVerified: false,
  fixtures: {},
  checks: [],
};
let pool;
let emitted = false;
function emit() {
  if (emitted) return;
  emitted = true;
  evidence.finished_at = new Date().toISOString();
  process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
}
const deadline = setTimeout(() => {
  evidence.status = 'failed';
  evidence.error = { kind: 'scenario_deadline', limit_ms: 60000 };
  emit();
  process.exit(1);
}, 60000);
function check(id, actual, pass) {
  evidence.checks.push({ id, pass: Boolean(pass), actual });
  if (!pass) throw new Error(`check_failed:${id}`);
}
async function request(method, path, token, company, body) {
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  if (company) headers['x-company-id'] = company;
  const response = await fetch(`http://127.0.0.1:5181/api${path}`, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(7000), redirect: 'error',
  });
  const json = await response.json();
  return { status: response.status, body: json };
}
try {
  if (!/^[a-zA-Z0-9_-]{8,80}$/.test(evidence.run_id)
      || !/^[a-f0-9]{64}$/.test(evidence.archive_sha256)) {
    throw new Error('invalid_run_binding');
  }
  const dsn = new URL(process.env.DATABASE_URL ?? '');
  if (dsn.hostname !== 'postgres' || dsn.pathname !== '/cumora_control'
      || dsn.username !== 'control' || (dsn.port && dsn.port !== '5432')
      || !['postgres:', 'postgresql:'].includes(dsn.protocol)
      || dsn.search || dsn.hash) throw new Error('not_dedicated_control_database');
  pool = new pg.Pool({ connectionString: dsn.href, max: 1,
    connectionTimeoutMillis: 3000, statement_timeout: 5000, query_timeout: 6000 });
  const suffix = randomBytes(10).toString('hex');
  const userA = `control-user-a-${suffix}`;
  const userB = `control-user-b-${suffix}`;
  const companyA = `control-company-a-${suffix}`;
  const companyB = `control-company-b-${suffix}`;
  const tokenA = randomBytes(32).toString('base64url');
  const tokenB = randomBytes(32).toString('base64url');
  const originalName = `Control original ${suffix}`;
  const updatedName = `Control updated ${suffix}`;
  const originalDescription = 'Disposable runtime scenario';
  const updatedDescription = 'Updated through authenticated HTTP';
  evidence.fixtures = { company_a: companyA, company_b: companyB,
    original_name: originalName, updated_name: updatedName,
    original_description: originalDescription, updated_description: updatedDescription };
  await pool.query('BEGIN');
  try {
    for (const [user, company, token] of [[userA, companyA, tokenA], [userB, companyB, tokenB]]) {
      await pool.query(`INSERT INTO users (id,email,display_name,password_hash,email_verified_at)
        VALUES ($1,$2,$3,'control-no-password-login',NOW())`, [user, `${user}@example.invalid`, user]);
      await pool.query(`INSERT INTO companies (id,name,slug,owner_user_id) VALUES ($1,$1,$1,$2)`, [company, user]);
      await pool.query(`INSERT INTO company_members (company_id,user_id,role) VALUES ($1,$2,'owner')`, [company, user]);
      await pool.query(`INSERT INTO sessions (token_hash,user_id,expires_at)
        VALUES ($1,$2,NOW() + INTERVAL '10 minutes')`, [createHash('sha256').update(token).digest('base64url'), user]);
    }
    await pool.query('COMMIT');
  } catch (error) { await pool.query('ROLLBACK'); throw error; }

  let result = await request('GET', '/projects', null, companyA);
  check('unauthenticated', { status: result.status }, result.status === 401);
  result = await request('POST', '/projects', tokenA, companyA,
    { name: originalName, description: originalDescription });
  const projectId = result.body?.id;
  evidence.fixtures.project_id = typeof projectId === 'string' ? projectId : null;
  check('create', result, result.status === 201 && typeof projectId === 'string'
    && /^p-[a-f0-9-]+$/.test(projectId) && result.body.name === originalName
    && result.body.description === originalDescription && result.body.status === 'active');
  async function rows() {
    return (await pool.query(`SELECT company_id,name,description,status,archived_at
      FROM projects WHERE id=$1`, [projectId])).rows.map(row => ({ ...row,
        archived_at: row.archived_at === null ? null : row.archived_at.toISOString() }));
  }
  const createdRows = await rows();
  check('db_created', { rows: createdRows }, isDeepStrictEqual(createdRows, [{
    company_id: companyA, name: originalName, description: originalDescription,
    status: 'active', archived_at: null }]));
  result = await request('GET', '/projects', tokenA, companyA);
  const ownerIds = Array.isArray(result.body) ? result.body.map(item => item.id) : null;
  check('list_owner', { status: result.status, ids: ownerIds },
    result.status === 200 && isDeepStrictEqual(ownerIds, [projectId]));
  result = await request('PUT', `/projects/${projectId}`, tokenA, companyA,
    { name: updatedName, description: updatedDescription });
  check('update_owner', result, result.status === 200 && result.body.ok === true);
  const updatedRows = await rows();
  check('db_updated', { rows: updatedRows }, isDeepStrictEqual(updatedRows, [{
    company_id: companyA, name: updatedName, description: updatedDescription,
    status: 'active', archived_at: null }]));
  result = await request('GET', '/projects', tokenB, companyB);
  const otherIds = Array.isArray(result.body) ? result.body.map(item => item.id) : null;
  check('list_other', { status: result.status, ids: otherIds },
    result.status === 200 && isDeepStrictEqual(otherIds, []));
  result = await request('PUT', `/projects/${projectId}`, tokenB, companyA, { name: 'forged tenant write' });
  check('forged_tenant', { status: result.status }, result.status === 403);
  result = await request('PUT', `/projects/${projectId}`, tokenB, companyB, { name: 'cross tenant write' });
  check('update_other', { status: result.status }, result.status === 404);
  const deniedRows = await rows();
  check('db_after_denials', { rows: deniedRows }, isDeepStrictEqual(deniedRows, updatedRows));
  result = await request('POST', `/projects/${projectId}/archive`, tokenA, companyA, { archive: true });
  check('archive_owner', result, result.status === 200 && result.body.ok === true && result.body.status === 'archived');
  const archivedRows = await rows();
  check('db_archived', { rows: archivedRows }, archivedRows.length === 1
    && archivedRows[0].company_id === companyA && archivedRows[0].name === updatedName
    && archivedRows[0].description === updatedDescription && archivedRows[0].status === 'archived'
    && typeof archivedRows[0].archived_at === 'string' && Number.isFinite(Date.parse(archivedRows[0].archived_at)));
  evidence.status = 'passed';
} catch (error) {
  // Never serialize connection strings, session tokens, headers or SQL parameters.
  evidence.error = { kind: error?.name ?? 'Error',
    reason: /^(check_failed:|invalid_run_binding$|not_dedicated_control_database$)/.test(error?.message ?? '')
      ? error.message : 'scenario_operation_failed', code: error?.code ?? null };
} finally {
  if (pool) {
    try { await pool.end(); }
    catch { evidence.status = 'failed'; evidence.error = { kind: 'pool_close_failed' }; }
  }
  clearTimeout(deadline);
  emit();
  process.exitCode = evidence.status === 'passed' ? 0 : 1;
}
