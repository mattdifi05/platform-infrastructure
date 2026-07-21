import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const routes = readFileSync(path.join(root, "traefik", "dynamic", "admin-routes.yml"), "utf8");
const routers = section(routes, "  routers:", "  middlewares:");
const middlewares = section(routes, "  middlewares:", "  services:");

test("database admin routing has no dedicated-host native login path", () => {
  assert.doesNotMatch(routers, /Host\(`phpmyadmin\./);
  assert.doesNotMatch(routers, /Host\(`phppgadmin\./);
});

test("every retained database admin router applies owner auth before other middleware", () => {
  for (const name of ["enterprise-phpmyadmin-portal-path", "enterprise-phppgadmin-portal-path"]) {
    const router = yamlBlock(routers, name, 4);
    assert.match(router, /service:\s+enterprise-(?:phpmyadmin|phppgadmin)/);
    const middlewareLines = router.match(/middlewares:\n((?:\s{8}-[^\n]+\n?)+)/)?.[1] || "";
    const names = [...middlewareLines.matchAll(/-\s+([^\s]+)/g)].map((match) => match[1]);
    assert.equal(names[0], "enterprise-db-admin-owner-auth@file", `${name} must authorize before rewriting or proxying`);
    assert.equal(names.filter((item) => item === "enterprise-db-admin-owner-auth@file").length, 1);
  }
});

test("database admin ForwardAuth trusts only the server-side session cookie", () => {
  const middleware = yamlBlock(middlewares, "enterprise-db-admin-owner-auth", 4);
  assert.match(middleware, /forwardAuth:/);
  assert.match(middleware, /address:\s+http:\/\/control-center:8080\/control\/internal\/database-admin-authorize/);
  assert.match(middleware, /trustForwardHeader:\s+false/);
  const forwarded = middleware.match(/authRequestHeaders:\n((?:\s{10}-[^\n]+\n?)+)/)?.[1] || "";
  assert.deepEqual([...forwarded.matchAll(/-\s+([^\s]+)/g)].map((match) => match[1]), ["Cookie"]);
  assert.doesNotMatch(middleware, /authResponseHeaders|role|subject|auth_time/i);
});

function section(text, startMarker, endMarker) {
  const start = text.indexOf(`${startMarker}\n`);
  const boundary = text.indexOf(`\n${endMarker}\n`, start + startMarker.length);
  assert.notEqual(start, -1, `missing ${startMarker}`);
  assert.notEqual(boundary, -1, `missing ${endMarker}`);
  return text.slice(start, boundary + 1);
}

function yamlBlock(text, name, indent) {
  const marker = `${" ".repeat(indent)}${name}:`;
  const start = text.indexOf(marker);
  assert.notEqual(start, -1, `missing YAML block ${name}`);
  const linePattern = new RegExp(`^ {${indent}}[^ \\n][^\\n]*:`, "gm");
  linePattern.lastIndex = start + marker.length;
  const next = linePattern.exec(text);
  return text.slice(start, next?.index ?? text.length);
}
