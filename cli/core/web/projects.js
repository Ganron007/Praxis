/**
 * Project registry for the web UI.
 * ============================================================================
 *
 * The security-relevant decision (threats T2/T3 in docs/design/WEB-UI.md): the browser
 * never sends a filesystem path.
 *
 * A client-supplied path would let any caller ask the server to scan `/`, read a home
 * directory, or enumerate the host — turning "scan my code" into arbitrary file
 * disclosure. So an operator registers projects here, by path, through the CLI or an
 * explicit API call, and the API thereafter addresses projects by **id** only.
 *
 * Each registered path is resolved once and pinned, so a symlink swapped afterwards
 * cannot silently redirect a scan somewhere else.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';

/** Hard ceiling so a runaway caller cannot fill the registry. */
export const MAX_PROJECTS = 64;

export function registryDir() {
  // Overridable so tests (and sandboxed runs) do not write into the real home
  // directory. Defaults to ~/.praxis/web, which is outside any scanned project so a
  // scan never picks up the UI's own state.
  const base = process.env.PRAXIS_WEB_HOME || path.join(os.homedir(), '.praxis', 'web');
  return base;
}

function registryPath() {
  return path.join(registryDir(), 'projects.json');
}

/**
 * Validates and pins a candidate project path.
 * @returns {{ok: true, root: string, name: string} | {ok: false, error: string}}
 */
export function resolveProject(candidate) {
  if (typeof candidate !== 'string' || candidate.trim() === '') {
    return { ok: false, error: 'path must be a non-empty string' };
  }
  let resolved;
  try {
    resolved = fs.realpathSync(path.resolve(candidate.trim()));
  } catch (err) {
    return { ok: false, error: `cannot resolve path: ${err.message}` };
  }
  let stat;
  try {
    stat = fs.statSync(resolved);
  } catch (err) {
    return { ok: false, error: `cannot stat path: ${err.message}` };
  }
  if (!stat.isDirectory()) {
    return { ok: false, error: 'project path must be a directory' };
  }
  return { ok: true, root: resolved, name: path.basename(resolved) || resolved };
}

/** Reads the registry; a missing or corrupt file yields an empty registry. */
export function readRegistry() {
  try {
    const data = JSON.parse(fs.readFileSync(registryPath(), 'utf8'));
    if (!data || !Array.isArray(data.projects)) return { projects: [] };
    return {
      projects: data.projects.filter(p => p && typeof p.id === 'string' && typeof p.root === 'string'),
    };
  } catch {
    return { projects: [] };
  }
}

function writeRegistry(state) {
  fs.mkdirSync(registryDir(), { recursive: true });
  fs.writeFileSync(registryPath(), JSON.stringify(state, null, 2), 'utf8');
}

/** Lists registered projects, annotated with whether the pinned path still exists. */
export function listProjects() {
  return readRegistry().projects.map(p => {
    let present = false;
    try {
      present = fs.statSync(p.root).isDirectory();
    } catch { present = false; }
    return { id: p.id, name: p.name, root: p.root, present };
  });
}

/**
 * Registers a project directory. Idempotent per resolved path.
 * @returns {{ok: true, project: object, created: boolean} | {ok: false, error: string}}
 */
export function addProject(candidate) {
  const resolved = resolveProject(candidate);
  if (!resolved.ok) return { ok: false, error: resolved.error };

  const state = readRegistry();
  const existing = state.projects.find(p => p.root === resolved.root);
  if (existing) {
    return { ok: true, project: existing, created: false };
  }
  if (state.projects.length >= MAX_PROJECTS) {
    return { ok: false, error: `registry is full (max ${MAX_PROJECTS} projects)` };
  }

  const project = {
    id: crypto.randomUUID(),
    name: resolved.name,
    root: resolved.root,
    addedAt: new Date().toISOString(),
  };
  state.projects.push(project);
  writeRegistry(state);
  return { ok: true, project, created: true };
}

/** Removes a project by id. */
export function removeProject(id) {
  const state = readRegistry();
  const before = state.projects.length;
  state.projects = state.projects.filter(p => p.id !== id);
  if (state.projects.length === before) return { ok: false, error: 'no such project' };
  writeRegistry(state);
  return { ok: true };
}

/**
 * Looks up a project by id. This is the only way the API turns a client value into a
 * path — a client-supplied path is never resolved here.
 *
 * Returns `{ok:false}` for an unknown id, and flags a project whose pinned path has
 * since disappeared so the caller can report that honestly rather than failing opaquely.
 */
export function getProject(id) {
  if (typeof id !== 'string' || id === '') return { ok: false, error: 'project id required' };
  const found = readRegistry().projects.find(p => p.id === id);
  if (!found) return { ok: false, error: 'unknown project id' };
  let present = true;
  try {
    present = fs.statSync(found.root).isDirectory();
  } catch { present = false; }
  return { ok: true, project: { ...found, present } };
}