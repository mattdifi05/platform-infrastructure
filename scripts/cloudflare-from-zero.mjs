#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

function parseArgs(args) {
  const out = { apply: false, createZone: false };
  for (let i = 0; i < args.length; i += 1) {
    const value = args[i];
    if (value === "--apply") {
      out.apply = true;
    } else if (value === "--create-zone") {
      out.createZone = true;
    } else if (value === "--manifest") {
      out.manifest = args[++i];
    } else if (value === "--account-id") {
      out.accountId = args[++i];
    } else if (value === "--help" || value === "-h") {
      out.help = true;
    } else {
      throw new Error(`Unknown argument: ${value}`);
    }
  }
  return out;
}

function usage() {
  process.stdout.write(`Usage: node scripts/cloudflare-from-zero.mjs --manifest cloudflare/from-zero.example.json [--apply] [--create-zone] [--account-id ID]\n\n`);
  process.stdout.write("Dry-run by default. In --apply mode this script only creates absent resources. It refuses DNS conflicts, never patches/deletes DNS, never overwrites an existing custom WAF entrypoint, and only applies zone settings to a zone created by this same run.\n");
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(path.resolve(file), "utf8"));
}

async function cloudflareRequest({ method, path: requestPath, body, token }) {
  const response = await fetch(`https://api.cloudflare.com/client/v4${requestPath}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await response.json().catch(() => ({}));
  if (!response.ok || json.success === false) {
    const errors = (json.errors || []).map((error) => `${error.code ?? "unknown"}: ${error.message}`).join("; ");
    throw new Error(`Cloudflare ${method} ${requestPath} failed (${response.status})${errors ? `: ${errors}` : ""}`);
  }
  return json;
}

function requireCleanRecord(record) {
  for (const key of ["type", "name", "content"]) {
    if (!record[key]) throw new Error(`DNS record is missing ${key}: ${JSON.stringify(record)}`);
  }
  if (record.proxied !== true && record.proxied !== false) {
    throw new Error(`DNS record must set proxied true/false explicitly: ${record.name}`);
  }
}

function normalizedDnsName(value) {
  return String(value).replace(/\.$/, "").toLowerCase();
}

function recordMatches(existing, desired) {
  const desiredTtl = desired.ttl ?? 1;
  return existing.type === desired.type
    && normalizedDnsName(existing.name) === normalizedDnsName(desired.name)
    && String(existing.content) === String(desired.content)
    && Boolean(existing.proxied) === Boolean(desired.proxied)
    && Number(existing.ttl ?? desiredTtl) === Number(desiredTtl);
}

function dnsConflicts(existingRecords, desired) {
  const sameName = existingRecords.filter((item) => normalizedDnsName(item.name) === normalizedDnsName(desired.name));
  const exact = sameName.find((item) => recordMatches(item, desired));
  if (exact) return { exact, conflicts: [] };

  const conflicts = sameName.filter((item) => (
    item.type === desired.type
    || item.type === "CNAME"
    || desired.type === "CNAME"
    || item.type === "NS"
    || desired.type === "NS"
  ));

  return { exact: undefined, conflicts };
}

async function main() {
  const argv = parseArgs(process.argv.slice(2));
  if (argv.help) {
    usage();
    return;
  }
  if (!argv.manifest) throw new Error("Missing --manifest.");

  const manifest = readJson(argv.manifest);
  if (!manifest.zoneName) throw new Error("Manifest must define zoneName.");

  const token = process.env.CLOUDFLARE_API_TOKEN;
  if (!token && argv.apply) throw new Error("Set CLOUDFLARE_API_TOKEN before --apply.");

  const records = manifest.dnsRecords || [];
  for (const record of records) requireCleanRecord(record);

  process.stdout.write(`==> Cloudflare from-zero plan for ${manifest.zoneName}\n`);
  process.stdout.write(argv.apply ? "Mode: apply\n" : "Mode: dry-run\n");

  if (!argv.apply) {
    process.stdout.write(`Would create ${records.length} DNS records only if absent.\n`);
    process.stdout.write(`Would apply ${manifest.settings?.length || 0} zone settings only to a zone created by this script.\n`);
    process.stdout.write(manifest.customWafRuleset ? "Would create one custom WAF entrypoint only if absent.\n" : "No custom WAF ruleset declared.\n");
    return;
  }

  const zones = await cloudflareRequest({
    method: "GET",
    path: `/zones?name=${encodeURIComponent(manifest.zoneName)}&per_page=50`,
    token,
  });
  let zone = zones.result?.[0];
  let createdZone = false;

  if (!zone && argv.createZone) {
    const accountId = argv.accountId || process.env.CLOUDFLARE_ACCOUNT_ID;
    if (!accountId) throw new Error("Creating a zone requires --account-id or CLOUDFLARE_ACCOUNT_ID.");
    const created = await cloudflareRequest({
      method: "POST",
      path: "/zones",
      token,
      body: { name: manifest.zoneName, account: { id: accountId }, type: "full" },
    });
    zone = created.result;
    createdZone = true;
    process.stdout.write(`Created zone ${manifest.zoneName}: ${zone.id}\n`);
  }

  if (!zone) {
    throw new Error(`Zone not found: ${manifest.zoneName}. Create it manually or pass --create-zone.`);
  }

  const dns = await cloudflareRequest({
    method: "GET",
    path: `/zones/${zone.id}/dns_records?per_page=500`,
    token,
  });
  const existingDns = dns.result || [];
  if (manifest.requireEmptyDns !== false && existingDns.length > 0) {
    throw new Error(`Refusing to bootstrap ${manifest.zoneName}: zone already has ${existingDns.length} DNS records.`);
  }

  if (manifest.settings?.length && !createdZone) {
    throw new Error("Refusing to change Cloudflare zone settings on an existing zone. Re-run with --create-zone only for a new zone, or review settings manually.");
  }

  for (const record of records) {
    const { exact, conflicts } = dnsConflicts(existingDns, record);
    if (exact) {
      process.stdout.write(`DNS already exists unchanged; left untouched: ${record.type} ${record.name}\n`);
      continue;
    }
    if (conflicts.length > 0) {
      const summary = conflicts.map((item) => `${item.type} ${item.name} -> ${item.content}`).join(", ");
      throw new Error(`Refusing DNS conflict for ${record.type} ${record.name}. Existing records left untouched: ${summary}`);
    }
    const created = await cloudflareRequest({
      method: "POST",
      path: `/zones/${zone.id}/dns_records`,
      token,
      body: { ttl: 1, ...record },
    });
    existingDns.push(created.result);
    process.stdout.write(`Created DNS ${created.result.type} ${created.result.name}\n`);
  }

  if (manifest.settings?.length) {
    for (const setting of manifest.settings) {
      if (!setting.id) throw new Error(`Cloudflare setting missing id: ${JSON.stringify(setting)}`);
      await cloudflareRequest({
        method: "PATCH",
        path: `/zones/${zone.id}/settings/${setting.id}`,
        token,
        body: { value: setting.value },
      });
      process.stdout.write(`Applied setting ${setting.id}\n`);
    }
  }

  if (manifest.customWafRuleset) {
    const listed = await cloudflareRequest({
      method: "GET",
      path: `/zones/${zone.id}/rulesets?per_page=100`,
      token,
    });
    const customExists = (listed.result || []).some((ruleset) => ruleset.phase === manifest.customWafRuleset.phase);
    if (customExists) {
      throw new Error("Refusing to modify existing Cloudflare custom WAF ruleset.");
    }
    const ruleset = manifest.customWafRuleset;
    await cloudflareRequest({
      method: "POST",
      path: `/zones/${zone.id}/rulesets`,
      token,
      body: {
        name: ruleset.name,
        description: ruleset.description,
        kind: "zone",
        phase: ruleset.phase,
        rules: ruleset.rules,
      },
    });
    process.stdout.write(`Created custom WAF entrypoint ${ruleset.name}\n`);
  }

  process.stdout.write("Cloudflare from-zero bootstrap completed.\n");
}

main().catch((error) => {
  process.stderr.write(`${error.message ?? error}\n`);
  process.exitCode = 1;
});
