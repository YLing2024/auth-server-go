#!/usr/bin/env node
// Route ↔ docs consistency check (zero dependencies).
//
// The Go route table in internal/httpapi/routes.go is the single source of
// truth for the HTTP surface. This script extracts every registered path from
// that table and every documented endpoint heading from docs/API.md, then fails
// (non-zero exit) when the two differ: a route without documentation, or a
// documented route that no longer exists. Wired into `make check`.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Extract route paths from the Go routeTable literals. */
function routesFromGo() {
  const src = readFileSync(join(root, 'internal/httpapi/routes.go'), 'utf8');
  const start = src.indexOf('var routeTable');
  if (start === -1) throw new Error('check-api-docs: routeTable not found in routes.go');
  const body = src.slice(start);
  const out = new Set();
  // Matches `{http.MethodGet, "/x", kind…}` and `{"", "/x", kind…}`.
  const re = /\{\s*(?:"[^"]*"|http\.Method[A-Za-z]+)\s*,\s*"([^"]+)"/g;
  let m;
  while ((m = re.exec(body)) !== null) out.add(m[1]);
  return out;
}

/** Extract `### <METHOD> <path>` headings from docs/API.md. */
function routesFromDocs() {
  const src = readFileSync(join(root, 'docs/API.md'), 'utf8');
  const out = new Set();
  const re = /^###\s+[A-Z]+\s+(\S+)/gm;
  let m;
  while ((m = re.exec(src)) !== null) out.add(m[1].split('?')[0]);
  return out;
}

const go = routesFromGo();
const docs = routesFromDocs();

const missing = [...go].filter((p) => !docs.has(p)).sort();
const extra = [...docs].filter((p) => !go.has(p)).sort();

if (missing.length === 0 && extra.length === 0) {
  console.log(`check-api-docs: OK (${go.size} routes documented)`);
  process.exit(0);
}

if (missing.length) console.error('check-api-docs: 路由缺少文档:\n  - ' + missing.join('\n  - '));
if (extra.length) console.error('check-api-docs: 文档多余（代码中无此路由）:\n  - ' + extra.join('\n  - '));
process.exit(1);
