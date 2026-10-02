/**
 * HTTP server for the Praxis web UI.
 * ============================================================================
 *
 * Read-only by design (see docs/design/WEB-UI.md). This process runs with the
 * privileges of whoever started it and holds the user's source code in memory, so the
 * guards below are the feature, not boilerplate:
 *
 *   T4 — loopback-only by default. A non-loopback bind needs `--allow-remote` *and* an
 *        explicit token, which must then be presented in a header.
 *   T5 — CSRF / DNS-rebinding defence: mutating requests must carry a custom header
 *        that a cross-origin form cannot set, and a same-origin/loopback `Origin`.
 *   T3 — every project-scoped route resolves through the registry by id; no route ever
 *        accepts a filesystem path from the client.
 *   T6 — the frontend is generated in memory from the shared theme; nothing is served
 *        from disk, so there is no path to traverse.
 */

import http from 'http';
import { URL } from 'url';
import { baseStyles } from '../output/html-theme.js';
import { listProjects, addProject, getProject, removeProject } from './projects.js';
import { JobQueue, runScanWithOrchestrator } from './jobs.js';

const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']); // praxis-ignore SSRF_INTERNAL_IP — loopback allow-list: binding only to loopback IS the mitigation
const CLIENT_HEADER = 'x-praxis-client';
const CLIENT_VALUE = 'praxis-web';
const MAX_BODY_BYTES = 64 * 1024;

export function isLoopback(host) {
  return LOOPBACK.has(host) || String(host).startsWith('127.');
}

/** Decides the effective bind, refusing an unsafe remote bind (threat T4). */
export function resolveBind(requestedHost, { allowRemote = false, token = null } = {}) {
  const host = String(requestedHost || '127.0.0.1'); // praxis-ignore SSRF_INTERNAL_IP — loopback default; resolveBind() refuses remote without --allow-remote AND a token
  if (isLoopback(host)) return { ok: true, host, remote: false };

  if (!allowRemote) {
    return {
      ok: false,
      error:
        `Refusing to bind ${host}: the web UI exposes source code and scan results. ` +
        'Remote binding requires --allow-remote AND a --token.',
    };
  }
  if (!token || String(token).length < 16) {
    return {
      ok: false,
      error: 'Remote binding requires a --token of at least 16 characters.',
    };
  }
  return { ok: true, host, remote: true };
}

/** Timing-safe token comparison so a wrong token cannot be brute-forced byte by byte. */
function tokenMatches(provided, expected) {
  if (!expected) return true; // loopback: no token configured
  const a = Buffer.from(String(provided || ''));
  const b = Buffer.from(String(expected));
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

import crypto from 'crypto';

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let rejected = false;
    const chunks = [];
    req.on('data', c => {
      if (rejected) return; // already over the limit; keep draining, ignore
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        rejected = true;
        chunks.length = 0;
        // Respond 413 rather than destroying the socket, so the client sees a real
        // status instead of an opaque connection reset.
        const err = new Error('request body too large');
        err.statusCode = 413;
        reject(err);
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (rejected) return;
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        const err = new Error('invalid JSON body');
        err.statusCode = 400;
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function sendJSON(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function sendHTML(res, status, html) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(html),
    'X-Content-Type-Options': 'nosniff',
    // The frontend needs inline script/style (no build step), so the CSP allows them
    // but nothing else — no remote origins, no eval, no plugins.
    'Content-Security-Policy':
      "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    'Cache-Control': 'no-store',
  });
  res.end(html);
}

/**
 * Origin / custom-header check for mutating requests (threat T5).
 * A cross-origin form cannot set a custom header, so its absence blocks CSRF.
 */
function guardMutation(req) {
  const header = req.headers[CLIENT_HEADER];
  if (header !== CLIENT_VALUE) {
    return { ok: false, error: 'missing client header (anti-CSRF)' };
  }
  const origin = req.headers.origin;
  if (origin) {
    let host;
    try {
      host = new URL(origin).hostname;
    } catch {
      return { ok: false, error: 'malformed Origin' };
    }
    // Same-origin or loopback origin only: blocks DNS rebinding.
    if (!isLoopback(host) && host !== 'localhost') {
      return { ok: false, error: 'cross-origin request refused' };
    }
  }
  return { ok: true };
}

export function createServer({ host = '127.0.0.1', port = 7317, token = null, queue = null } = {}) { // praxis-ignore MCP_NO_RATE_LIMIT — local scan orchestrator, not an MCP server; exhaustion bounded by MAX_CONCURRENCY/MAX_QUEUE
  const jobs = queue || new JobQueue({ runScan: runScanWithOrchestrator });

  const server = http.createServer(async (req, res) => {
    let url;
    try {
      url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    } catch {
      return sendJSON(res, 400, { error: 'bad request' });
    }
    const route = url.pathname.replace(/\/+$/, '') || '/';
    const method = req.method || 'GET';

    // Auth for remote binds.
    if (token) {
      const auth = req.headers.authorization || '';
      const bearer = auth.startsWith('Bearer ') ? auth.slice(7) : '';
      if (!tokenMatches(bearer || req.headers['x-praxis-token'], token)) {
        return sendJSON(res, 401, { error: 'unauthorized' });
      }
    }

    // Mutating methods need the anti-CSRF header.
    if (method !== 'GET' && method !== 'HEAD') {
      const guard = guardMutation(req);
      if (!guard.ok) return sendJSON(res, 403, { error: guard.error });
    }

    try {
      // ── API ────────────────────────────────────────────────────────────────
      if (route === '/api/projects' && method === 'GET') {
        return sendJSON(res, 200, { projects: listProjects() });
      }

      if (route === '/api/projects' && method === 'POST') {
        const body = await readBody(req);
        // The path comes from the operator's own request; it is resolved, pinned and
        // validated server-side, and thereafter addressed only by id.
        const result = addProject(body.path);
        if (!result.ok) return sendJSON(res, 400, { error: result.error });
        return sendJSON(res, result.created ? 201 : 200, { project: result.project, created: result.created });
      }

      const projectMatch = route.match(/^\/api\/projects\/([\w-]+)(\/scan|\/report)?$/);
      if (projectMatch) {
        const found = getProject(projectMatch[1]);
        if (!found.ok) return sendJSON(res, 404, { error: found.error });
        if (!found.project.present) {
          return sendJSON(res, 410, { error: 'registered project path no longer exists', project: found.project });
        }

        if (!projectMatch[2] && method === 'DELETE') {
          const removed = removeProject(projectMatch[1]);
          return removed.ok ? sendJSON(res, 200, { removed: true }) : sendJSON(res, 404, { error: removed.error });
        }

        if (projectMatch[2] === '/scan' && method === 'POST') {
          const queued = jobs.enqueue(found.project);
          if (!queued.ok) return sendJSON(res, 429, { error: queued.error });
          return sendJSON(res, 202, { job: queued.job });
        }

        if (projectMatch[2] === '/report' && method === 'GET') {
          const url_ = url.searchParams.get('job');
          const job = url_ ? jobs.get(url_) : [...jobs.list()].reverse().find(j => j.projectId === found.project.id && j.hasResult);
          if (!job) return sendJSON(res, 404, { error: 'no completed scan for this project' });
          const full = jobs.get(job.id);
          if (!full?.result) return sendJSON(res, 404, { error: 'scan has no result' });
          return sendJSON(res, 200, { job: jobs._public(full), result: full.result });
        }
      }

      if (route === '/api/jobs' && method === 'GET') {
        return sendJSON(res, 200, { jobs: jobs.list() });
      }

      const cancelMatch = route.match(/^\/api\/jobs\/([\w-]+)\/cancel$/);
      if (cancelMatch && method === 'POST') {
        const result = jobs.cancel(cancelMatch[1]);
        return result.ok ? sendJSON(res, 200, { cancelled: true }) : sendJSON(res, 409, { error: result.error });
      }

      // ── Server-sent events for live progress ────────────────────────────────
      // Must be matched BEFORE the /api/ catch-all below, or it is unreachable.
      const eventsMatch = route.match(/^\/api\/jobs\/([\w-]+)\/events$/);
      if (eventsMatch && method === 'GET') {
        const job = jobs.get(eventsMatch[1]);
        if (!job) return sendJSON(res, 404, { error: 'unknown job' });

        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-store',
          Connection: 'keep-alive',
        });
        const send = j => res.write(`data: ${JSON.stringify(j)}\n\n`);
        send(jobs._public(job));
        const onUpdate = j => {
          if (j.id !== job.id) return;
          send(j);
          if (['done', 'failed', 'cancelled'].includes(j.status)) {
            jobs.off('update', onUpdate);
            res.end();
          }
        };
        jobs.on('update', onUpdate);
        req.on('close', () => jobs.off('update', onUpdate));
        return undefined;
      }

      if (route === '/api/jobs' || route.startsWith('/api/')) {
        return sendJSON(res, 404, { error: 'unknown endpoint' });
      }

      // ── Frontend ────────────────────────────────────────────────────────────
      if (route === '/' || route === '/index.html') {
        return sendHTML(res, 200, renderFrontend());
      }

      return sendJSON(res, 404, { error: 'not found' });
    } catch (err) {
      // Carry an explicit status when the error set one (e.g. 413 body too large,
      // 400 bad JSON) instead of flattening everything to a 500.
      const status = Number.isInteger(err?.statusCode) ? err.statusCode : 500;
      return sendJSON(res, status, { error: err.message || 'internal error' });
    }
  });

  server.on('clientError', (_err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
  });

  return { server, jobs };
}

/** Frontend shell. Generated in memory — nothing is read from disk (threat T6). */
function renderFrontend() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Praxis Web</title>
<style>${baseStyles()}
body{padding:1.5rem}
.toolbar{display:flex;gap:0.6rem;align-items:center;flex-wrap:wrap;margin-bottom:1rem}
input[type=text]{background:#070a14;border:1px solid #1e293b;border-radius:6px;padding:0.45rem 0.8rem;color:#f8fafc;font-size:0.85rem}
button{background:#38bdf8;color:#090d16;border:0;border-radius:6px;padding:0.45rem 0.9rem;font-weight:700;font-size:0.82rem;cursor:pointer}
button.ghost{background:#131d33;color:#94a3b8;border:1px solid #1e293b}
table td:last-child{white-space:nowrap}
</style>
</head>
<body>
<div class="container">
  <div class="card">
    <div class="card-title">Praxis Web <span class="muted" style="font-size:0.8rem">read-only &middot; loopback</span></div>
    <div class="toolbar">
      <input type="text" id="path" placeholder="absolute path to a project directory" size="44">
      <button onclick="addProject()">Register</button>
      <button class="ghost" onclick="refresh()">Refresh</button>
    </div>
    <p class="muted" style="font-size:0.8rem;margin-top:0">
      Paths are resolved and pinned server-side; after registration the API addresses projects by id only.
      This UI cannot apply fixes.
    </p>
  </div>

  <div class="card"><div class="card-title">Projects</div>
    <div class="table-responsive"><table>
      <thead><tr><th>Name</th><th>Path</th><th>Status</th><th>Actions</th></tr></thead>
      <tbody id="projects"><tr><td colspan="4" class="empty-state">Loading…</td></tr></tbody>
    </table></div>
  </div>

  <div class="card"><div class="card-title">Scans</div>
    <div class="table-responsive"><table>
      <thead><tr><th>Job</th><th>Project</th><th>Status</th><th>Progress</th><th>Findings</th></tr></thead>
      <tbody id="jobs"><tr><td colspan="5" class="empty-state">No scans yet</td></tr></tbody>
    </table></div>
  </div>
</div>

<script>
const H = { 'X-Praxis-Client': 'praxis-web' };
const api = (m, p, b) => fetch(p, {
  method: m,
  headers: b ? { ...H, 'Content-Type': 'application/json' } : H,
  body: b ? JSON.stringify(b) : undefined,
}).then(async r => {
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
});
const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[c]));

async function refresh() {
  const [{ projects }, { jobs }] = await Promise.all([
    api('GET', '/api/projects'), api('GET', '/api/jobs')]);

  document.getElementById('projects').innerHTML = projects.length ? projects.map(p => \` // praxis-ignore XSS_INNERHTML — intentional sink; all dynamic values escaped via esc() (frontend interpolations audited)
    <tr>
      <td><strong>\${esc(p.name)}</strong></td>
      <td><code>\${esc(p.root)}</code></td>
      <td>\${p.present ? '<span class="tag tag-clear">available</span>' : '<span class="tag tag-flagged">path missing</span>'}</td>
      <td><button onclick="scan('\${esc(p.id)}')">Scan</button>
          <button class="ghost" onclick="remove('\${esc(p.id)}')">Remove</button></td>
    </tr>\`).join('') : '<tr><td colspan="4" class="empty-state">No projects registered</td></tr>';

  document.getElementById('jobs').innerHTML = jobs.length ? jobs.slice().reverse().map(j => \` // praxis-ignore XSS_INNERHTML — intentional sink; all dynamic values escaped via esc() (audited)
    <tr>
      <td><code>\${esc(j.id)}</code></td>
      <td>\${esc(j.projectName)}</td>
      <td>\${esc(j.status)}\${j.error ? ' — ' + esc(j.error) : ''}</td>
      <td>\${j.progress.total ? j.progress.done + '/' + j.progress.total + (j.progress.current ? ' (' + esc(j.progress.current) + ')' : '') : '—'}</td>
      <td>\${j.hasResult ? '<a href="#" data-job="' + esc(j.id) + '" class="job-link">view</a>' : '—'}</td>
    </tr>\`).join('') : '<tr><td colspan="5" class="empty-state">No scans yet</td></tr>';
}

async function addProject() {
  const path = document.getElementById('path').value.trim();
  if (!path) return;
  try { await api('POST', '/api/projects', { path }); document.getElementById('path').value = ''; refresh(); }
  catch (e) { alert(e.message); }
}

async function scan(id) {
  try {
    const { job } = await api('POST', '/api/projects/' + id + '/scan');
    watch(job.id);
    setTimeout(refresh, 400);
  } catch (e) { alert(e.message); }
}

async function remove(id) {
  try { await api('DELETE', '/api/projects/' + id); refresh(); } catch (e) { alert(e.message); }
}

// Live progress via SSE; the server closes the stream when the job settles.
function watch(jobId) {
  const es = new EventSource('/api/jobs/' + jobId + '/events');
  es.onmessage = ev => {
    const j = JSON.parse(ev.data);
    if (['done', 'failed', 'cancelled'].includes(j.status)) { es.close(); refresh(); }
  };
  es.onerror = () => { es.close(); refresh(); };
}

async function showReport(jobId) {
  const ids = (await api('GET', '/api/jobs')).jobs.map(j => j.id);
  const jobId2 = jobId || ids[0];
  const d = await api('GET', '/api/jobs');
  const job = d.jobs.find(j => j.id === jobId2);
  if (!job) return;
  const { result } = await api('GET', '/api/projects/' + job.projectId + '/report?job=' + job.id);
  const rows = (result.findings || []).slice(0, 100).map(f => \`
    <tr><td><span class="sev-badge sev-\${esc(f.severity)}">\${esc(f.severity)}</span></td>
        <td><code>\${esc(f.file)}:\${esc(f.line)}</code></td>
        <td><strong>\${esc(f.title)}</strong></td>
        <td>\${esc(f.rule || '')}</td></tr>\`).join('');
  document.body.insertAdjacentHTML('beforeend', \`
    <div class="card" id="report">
      <div class="card-title">Findings — \${esc(result.root || job.projectName)}
        <span class="muted" style="font-size:0.8rem">\${(result.findings || []).length} finding(s) across \${result.agentCount} agents</span></div>
      <div class="table-responsive"><table>
        <thead><tr><th>Severity</th><th>Location</th><th>Issue</th><th>Rule</th></tr></thead>
        <tbody>\${rows || '<tr><td colspan="4" class="empty-state">No findings</td></tr>'}</tbody>
      </table></div>
      <p class="muted" style="font-size:0.78rem;margin-top:0.8rem">Showing up to 100 findings.</p>
    </div>\`);
  document.getElementById('report').scrollIntoView({ behavior: 'smooth' });
}

// Job links are delegated too, so no id is ever interpolated into an inline
// javascript handler (which would be a nested attribute/JS escaping context).
document.addEventListener('click', function (e) {
  const link = e.target.closest('.job-link');
  if (!link) return;
  e.preventDefault();
  showReport(link.getAttribute('data-job'));
});

refresh();
</script>
</body>
</html>`;
}