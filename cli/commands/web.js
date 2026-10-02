/**
 * `praxis web` — local web UI for driving scans and managing scan projects.
 *
 * Read-only by design: it orchestrates scans and shows results, and deliberately does
 * NOT expose fix application. See docs/design/WEB-UI.md for the threat model.
 */

import { createServer, resolveBind, isLoopback } from '../core/web/server.js';
import { runScanWithOrchestrator, JobQueue } from '../core/web/jobs.js';
import { listProjects } from '../core/web/projects.js';
import * as output from '../utils/output.js';

export async function webCommand(options = {}) {
  const host = options.host || '127.0.0.1'; // praxis-ignore SSRF_INTERNAL_IP — loopback default; resolveBind() enforces the remote-bind policy
  const port = parseInt(options.port || '7317', 10);
  const allowRemote = Boolean(options.allowRemote);
  const token = options.token || process.env.PRAXIS_WEB_TOKEN || null;

  const bind = resolveBind(host, { allowRemote, token });
  if (!bind.ok) {
    output.error(bind.error);
    process.exitCode = 1;
    return;
  }

  const { server, jobs } = createServer({
    host: bind.host,
    port,
    token: bind.remote ? token : null,
    queue: new JobQueue({ runScan: runScanWithOrchestrator }),
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, bind.host, resolve);
  });

  const actual = server.address();
  output.success(`Praxis Web listening on http://${bind.host}:${actual.port}`);
  if (bind.remote) {
    output.warn('REMOTE BIND — this server exposes source code and scan results. Anyone who can reach it, and knows the token, can read them.');
  } else {
    output.info('Loopback only. Use --allow-remote --token <16+ chars> to expose it deliberately.');
  }

  const registered = listProjects();
  output.info(registered.length
    ? `${registered.length} project(s) already registered.`
    : 'No projects registered yet — add one from the UI, or POST /api/projects.');

  output.info('This UI is read-only: it cannot apply fixes. Use `praxis fix` for remediation.');

  const shutdown = () => {
    output.info('\nShutting down…');
    server.close(() => process.exit(0));
    // Do not let a hung SSE connection block exit forever.
    setTimeout(() => process.exit(0), 2000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  return { server, jobs, isLoopback: isLoopback(bind.host) };
}