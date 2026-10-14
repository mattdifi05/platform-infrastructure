#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import { createCloudflareVisibilityProvider } from '../providers/cloudflare-access.mjs';

// Run on the host with the service's protected environment already loaded, or
// node --env-file=/root/<protected-env> control-center/hosting/verify-cloudflare-visibility.mjs
// This command never reads application content or invokes visibility apply.
export async function verifyCloudflareVisibility({ env = process.env, fetchImpl = fetch } = {}) {
  let requests = 0;
  const readOnlyFetch = async (url, options = {}) => {
    if ((options.method || 'GET') !== 'GET') throw Error('Read-only visibility verifier refused a mutation');
    requests += 1;
    return fetchImpl(url, options);
  };
  const provider = createCloudflareVisibilityProvider({ env, fetchImpl: readOnlyFetch });
  const results = [];
  for (const project of provider.listProjects()) {
    try {
      const status = await provider.getVisibility(project);
      const plan = await provider.planVisibility(project, 'private');
      results.push({ project, status, privatePlan: { revision: plan.revision, currentMode: plan.currentMode,
        requestedMode: plan.requestedMode, actions: plan.actions, dryRun: plan.dryRun, providerTouched: plan.providerTouched } });
    } catch {
      // Deliberately omit provider exception details, response bodies and config
      // file paths so no credential can escape through a future transport error.
      results.push({ project, error: 'Provider inventory or exact ownership verification failed' });
    }
  }
  return { readOnly: true, providerTouched: false, requests, healthy: results.every(result => !result.error), results };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await verifyCloudflareVisibility();
    console.log(JSON.stringify(result, null, 2));
    if (!result.healthy) process.exitCode = 1;
  } catch {
    console.error('Protected Cloudflare visibility configuration or read-only provider verification unavailable');
    process.exitCode = 1;
  }
}
