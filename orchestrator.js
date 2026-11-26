'use strict';
// Scope-gated local review orchestrator.
// Refuses to run unless a current, owner/program-authorized scope file covers the target path.
// Runs only the repository's offline source analyzers; no network, no target discovery,
// no execution of inspected code, no submission. Output is a ranked queue of UNVERIFIED leads.
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const MAX_AGE_DAYS = 7;
const AUTH = new Set(['owner_or_explicit_permission', 'program_scope_read_and_eligible']);
const ANALYZERS = [
  // priority: lower = reviewed first. Authorization-logic gaps outrank configuration observations.
  { name: 'authz-review', script: 'authz-review.py', priority: 1 },
  { name: 'python-defaults-review', script: 'python-defaults-review.py', priority: 2, perDirectory: true },
  { name: 'digest-review', script: 'digest-review.py', priority: 3, perDirectory: true },
];

function checkScope(scope, target, now = new Date()) {
  const fail = (reason) => { throw Object.assign(new Error(reason), { blocked: true }); };
  if (!scope || scope.schema_version !== 1) fail('scope schema_version 1 required');
  if (!AUTH.has(scope.authorization)) fail('authorization must be owner_or_explicit_permission or program_scope_read_and_eligible');
  if (typeof scope.program !== 'string' || !scope.program) fail('program name required');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(scope.as_of || '')) fail('as_of (YYYY-MM-DD) required: the date you last read the current rules');
  const asOf = new Date(scope.as_of + 'T00:00:00Z');
  if (Number.isNaN(asOf.getTime())) fail('as_of is not a valid date');
  const ageDays = (now - asOf) / 86400000;
  if (ageDays < -1) fail('as_of is in the future');
  if (ageDays > MAX_AGE_DAYS) fail(`scope is stale (${Math.floor(ageDays)} days old; re-read the current rules and update as_of)`);
  if (!Array.isArray(scope.methods_permitted) || !scope.methods_permitted.includes('local_source_analysis')) {
    fail('methods_permitted must include local_source_analysis');
  }
  if (!Array.isArray(scope.source_roots) || scope.source_roots.length === 0) fail('source_roots required');
  let real;
  try { real = fs.realpathSync(target); } catch { fail('target does not exist'); }
  const covered = scope.source_roots.some((root) => {
    let r;
    try { r = fs.realpathSync(root); } catch { return false; }
    const rel = path.relative(r, real);
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
  });
  if (!covered) fail('target is outside every source_root in the scope file');
  return { target: real, as_of: scope.as_of, age_days: Math.max(0, Math.floor(ageDays)) };
}

function pythonDirs(target) {
  // The older analyzers read only the immediate .py files of a directory, so run them once per directory.
  const skip = new Set(['node_modules', '.git', 'venv', '.venv', '__pycache__']);
  if (!fs.statSync(target).isDirectory()) return [target];
  const dirs = [];
  const walk = (d, depth) => {
    const entries = fs.readdirSync(d, { withFileTypes: true });
    if (entries.some((e) => e.isFile() && e.name.endsWith('.py'))) dirs.push(d);
    if (depth < 8) for (const e of entries) if (e.isDirectory() && !e.isSymbolicLink() && !skip.has(e.name)) walk(path.join(d, e.name), depth + 1);
  };
  walk(target, 0);
  return dirs;
}

function runAnalyzer(a, target) {
  if (a.perDirectory) {
    const runs = pythonDirs(target).map((d) => runAnalyzer({ ...a, perDirectory: false }, d));
    if (runs.some((r) => !r.ok)) return { name: a.name, ok: false };
    return { name: a.name, ok: true, priority: a.priority, data: { results: runs.flatMap((r) => r.data.results || []) } };
  }
  let stdout;
  try {
    stdout = execFileSync('python3', [path.join(__dirname, a.script), 'review', target, '--authorized-local'],
      { encoding: 'utf8', timeout: 120000, maxBuffer: 32 * 1024 * 1024 });
  } catch (e) {
    if (e.status === 3 && e.stdout) stdout = e.stdout; // exit 3 = leads present
    else return { name: a.name, ok: false };
  }
  try { return { name: a.name, ok: true, data: JSON.parse(stdout), priority: a.priority }; } catch { return { name: a.name, ok: false }; }
}

function normalize(run) {
  const leads = [];
  for (const entry of run.data.results || []) {
    const items = Array.isArray(entry.findings) ? entry.findings.map((f) => ({ filename: entry.filename, ...f })) : [entry];
    for (const it of items) {
      leads.push({
        analyzer: run.name, priority: run.priority, file: it.filename, line: it.line ?? it.line_number ?? null,
        rule: it.rule ?? it.status ?? 'observation', status: 'unverified_lead',
        needs_review_note: it.status === 'needs_review_global_auth_possible' ? 'global auth control may apply' : undefined,
        message: it.message ?? it.algorithm ?? undefined,
      });
    }
  }
  return leads;
}

function orchestrate(scope, target, now) {
  const ctx = checkScope(scope, target, now);
  const runs = ANALYZERS.map((a) => runAnalyzer(a, ctx.target));
  const failed = runs.filter((r) => !r.ok).map((r) => r.name);
  const leads = runs.filter((r) => r.ok).flatMap(normalize)
    .sort((x, y) => x.priority - y.priority || String(x.file).localeCompare(String(y.file)) || (x.line ?? 0) - (y.line ?? 0));
  return {
    status: failed.length ? 'PARTIAL_REVIEW' : 'LOCAL_REVIEW_COMPLETE', program: scope.program, scope_as_of: ctx.as_of,
    analyzers_run: runs.filter((r) => r.ok).map((r) => r.name), analyzers_failed: failed, lead_count: leads.length,
    review_queue: leads,
    next_steps: 'Verify each lead by hand within the program rules, reproduce only where the rules permit, and use `node research.js report` checks before any submission. Nothing here is a confirmed finding.',
    notice: 'Unverified leads only. No network, execution of inspected code, or submission. Clean output is not an assurance of security.',
  };
}

function selftest() {
  let passed = 0;
  const ok = (c, m) => { if (!c) throw new Error('FAIL: ' + m); passed++; };
  const os = require('node:os');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orch-'));
  const root = path.join(dir, 'proj'); fs.mkdirSync(root);
  const outside = path.join(dir, 'other'); fs.mkdirSync(outside);
  const src = "@app.route('/i/<int:item_id>')\n@login_required\ndef g(item_id):\n    return Item.query.get(item_id)\n";
  fs.writeFileSync(path.join(root, 'a.py'), src);
  fs.writeFileSync(path.join(outside, 'b.py'), src);
  const now = new Date('2026-11-25T12:00:00Z');
  const good = { schema_version: 1, program: 'demo', authorization: 'owner_or_explicit_permission', as_of: '2026-11-24',
    methods_permitted: ['local_source_analysis'], source_roots: [root] };
  const blocked = (scope, t) => { try { orchestrate(scope, t, now); return false; } catch (e) { return e.blocked === true; } };
  ok(blocked({ ...good, as_of: '2026-11-10' }, root), 'stale scope blocked');
  ok(blocked({ ...good, as_of: '2026-12-30' }, root), 'future date blocked');
  ok(blocked({ ...good, authorization: 'trust_me' }, root), 'bad authorization blocked');
  ok(blocked({ ...good, methods_permitted: ['live_scanning'] }, root), 'unsupported method blocked');
  ok(blocked({ ...good, source_roots: [] }, root), 'empty roots blocked');
  ok(blocked(good, outside), 'out-of-scope target blocked');
  ok(blocked(good, path.join(root, '..', 'other')), 'path traversal blocked');
  ok(blocked(null, root), 'missing scope blocked');
  fs.symlinkSync(outside, path.join(root, 'link'));
  ok(blocked(good, path.join(root, 'link')), 'symlink escape blocked');
  const r = orchestrate(good, root, now);
  ok(r.status === 'LOCAL_REVIEW_COMPLETE', 'complete run');
  ok(r.review_queue.some((l) => l.analyzer === 'authz-review' && l.rule === 'missing_object_authorization'), 'authz lead surfaced');
  ok(r.review_queue.every((l) => l.status === 'unverified_lead'), 'leads never marked confirmed');
  ok(r.review_queue[0].priority === 1, 'authorization leads ranked first');
  fs.rmSync(dir, { recursive: true, force: true });
  console.log(JSON.stringify({ passed, failed: 0, scope: 'authored local gate and integration tests' }, null, 2));
}

if (require.main === module) {
  const a = process.argv.slice(2);
  if (a.length === 1 && a[0] === 'test') selftest();
  else if (a.length === 4 && a[0] === 'run' && a[3] === '--authorized-local') {
    try {
      const out = orchestrate(JSON.parse(fs.readFileSync(a[1], 'utf8')), a[2]);
      console.log(JSON.stringify(out, null, 2));
      process.exit(out.status === 'LOCAL_REVIEW_COMPLETE' ? (out.lead_count ? 3 : 0) : 3);
    } catch (e) {
      console.error(e.blocked ? `BLOCKED: ${e.message}` : 'Invalid scope or input');
      process.exit(1);
    }
  } else {
    console.error('Usage: node orchestrator.js test | run SCOPE.json TARGET --authorized-local');
    process.exit(1);
  }
}
module.exports = { checkScope, orchestrate };
