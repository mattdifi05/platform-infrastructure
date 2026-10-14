import { randomUUID } from 'node:crypto';
const terminal = new Set(['available', 'failed', 'activation_failed', 'cancelled', 'interrupted']);
const keys = (value, allowed) => { if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !allowed.includes(key))) throw Error('Unsupported hosting payload'); };
export function createHostingLifecycle({ provider, native, store, registerProject, audit = () => {}, now = () => Date.now() }) {
  let running = false;
  const visibilityBusy = new Set();
  const cloneAdmissions = new Set();
  const read = () => store.read('hostingJobs', { strict: true }).value;
  const save = job => { const state = read(); if (state.jobs[job.requestId]?.cancelRequested) job.cancelRequested = true; state.jobs[job.requestId] = job; store.write('hostingJobs', state); };
  const admitted = id => { if (!provider) throw Error('Cloudflare visibility is not configured'); return provider.getProject(id); };
  const bind = (job, row) => { if (row.requestId !== job.requestId || row.sourceId !== job.sourceId || row.targetId !== job.targetId) throw Error('Native job binding mismatch'); return row; };
  const receipt = async target => {
    const visibility = await provider.getVisibility(target);
    if (visibility.effective !== 'private' || visibility.verified !== true || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(visibility.accessApplicationId || '')) throw Error('Private publication is not verified');
    return { hostname: target.hostname, verifiedAt: Math.floor(now() / 1000), accessApplicationId: visibility.accessApplicationId };
  };
  async function tick() {
    if (running || !provider) return; running = true;
    try { for (const job of Object.values(read().jobs)) {
      if (visibilityBusy.has(job.targetId)) continue;
      if (terminal.has(job.status) && !(job.status === 'available' && (!job.registered || job.cancelRequested))) continue;
      try {
        const target = admitted(job.targetId);
        if (job.status === 'authorized') {
          const plan = await provider.planVisibility(target, 'private');
          await provider.applyVisibility(plan, { expectedRevision: plan.revision, confirm: plan.confirmationRequired });
          await receipt(target);
          if (read().jobs[job.requestId]?.cancelRequested) { job.status = 'cancelled'; save(job); continue; }
          const row = bind(job, await native({ operation: 'clone', requestId: job.requestId, sourceId: job.sourceId, targetId: job.targetId }));
          job.status = row.status; job.result = row.result; save(job);
        }
        let row = bind(job, await native({ operation: 'status', requestId: job.requestId }));
        if (read().jobs[job.requestId]?.cancelRequested) row = bind(job, await native({ operation: 'cancel', requestId: job.requestId }));
        if (row.status === 'staged' && !read().jobs[job.requestId]?.cancelRequested) {
          row = bind(job, await native({ operation: 'activate', requestId: job.requestId, publication: await receipt(target) }));
        }
        if (read().jobs[job.requestId]?.cancelRequested && row.status === 'available') row = bind(job, await native({ operation: 'cancel', requestId: job.requestId }));
        job.status = row.status; job.result = row.result; job.updatedAt = new Date(now()).toISOString(); delete job.error; save(job);
        if (row.status === 'cancelled' && job.registered) registerProject({ ...job, hostname: target.hostname });
        if (row.status === 'available' && !job.registered) { registerProject({ ...job, hostname: target.hostname }); job.registered = true; save(job); audit('project.clone.available', job.targetId); }
      } catch { job.error = 'Publication or native operation unavailable; authorized job retained for retry'; save(job); }
    } } finally { running = false; }
  }
  return {
    tick,
    async status(id) {
      let project, visibility, reason = null, eligible = false, hostname = null;
      try { project = admitted(id); visibility = await provider.getVisibility(project); const target = project.isClone ? project : admitted(`local-${id}`); hostname = target.hostname;
        const profiles = await native({ operation: 'list' }); eligible = !project.isClone && profiles.apps.some(app => app.id === id && app.domain === project.hostname && app.baseDomain === project.baseDomain); if (!eligible) reason = 'Source not admitted by native application operator';
      } catch { reason = 'Hosting provider or native application operator unavailable'; }
      const job = Object.values(read().jobs).filter(job => job.sourceId === id || job.targetId === id).at(-1);
      if (job) { eligible = false; reason = 'Deterministic clone destination is already reserved'; }
      return { ok: true, project: { slug: id, productionHostname: project?.hostname || null, visibility: visibility || { desired: 'unknown', effective: 'unknown', verified: false, updatedAt: null } }, privateCopy: { hostname, status: job?.status || 'absent', jobId: job?.requestId || null, requestId: job?.requestId || null, cancellable: Boolean(job && !['cancelled', 'failed', 'interrupted'].includes(job.status)), eligible, reason } };
    },
    async plan(id, mode) { return provider.planVisibility(admitted(id), mode); },
    async visibility(id, payload) {
      keys(payload, ['mode', 'expectedRevision', 'confirm']);
      if (visibilityBusy.has(id) || cloneAdmissions.has(id) || Object.values(read().jobs).some(job => job.targetId === id && !terminal.has(job.status))) throw Error('Clone publication is in progress');
      visibilityBusy.add(id);
      try {
        const plan = await provider.planVisibility(admitted(id), payload.mode);
        if (plan.revision !== payload.expectedRevision || plan.confirmationRequired !== payload.confirm) throw Error('Visibility plan changed or confirmation missing');
        const result = await provider.applyVisibility(plan, { expectedRevision: payload.expectedRevision, confirm: payload.confirm }); audit('project.visibility', id); return result;
      } finally { visibilityBusy.delete(id); }
    },
    async clone(id, payload) {
      keys(payload, ['confirm']); if (payload.confirm !== `CLONE-PRIVATE:${id}`) throw Error('Clone confirmation missing');
      const source = admitted(id); if (source.isClone) throw Error('A clone cannot be cloned');
      const target = admitted(`local-${id}`);
      if (visibilityBusy.has(target.id) || cloneAdmissions.has(target.id)) throw Error('Clone target operation is in progress');
      cloneAdmissions.add(target.id);
      try {
      const profiles = await native({ operation: 'list' });
      if (!profiles.apps.some(app => app.id === id && app.domain === source.hostname && app.baseDomain === source.baseDomain)) throw Error('Native source admission mismatch');
      if (Object.values(read().jobs).some(job => job.targetId === target.id)) throw Error('Clone target already reserved');
      const requestId = randomUUID(); await native({ operation: 'plan', requestId, sourceId: id, targetId: target.id });
      if (Object.values(read().jobs).some(job => job.targetId === target.id)) throw Error('Clone target already reserved');
      const job = { requestId, sourceId: id, targetId: target.id, status: 'authorized', createdAt: new Date(now()).toISOString() }; save(job); audit('project.clone.authorized', id); void tick(); return job;
      } finally { cloneAdmissions.delete(target.id); }
    },
    async cancel(id, requestId, payload) {
      keys(payload, ['confirm']); if (payload.confirm !== `CANCEL-CLONE:${requestId}`) throw Error('Cancellation confirmation missing');
      const job = read().jobs[requestId]; if (!job || ![job.sourceId, job.targetId].includes(id)) throw Error('Clone job not bound to project');
      job.cancelRequested = true; save(job);
      if (job.status === 'authorized' && !running) job.status = 'cancelled'; else {
        try { const row = bind(job, await native({ operation: 'cancel', requestId })); job.status = row.status; job.result = row.result; }
        catch { job.error = 'Cancellation persisted; native confirmation pending'; }
      }
      save(job); if (job.registered && job.status === 'cancelled') registerProject({ ...job, hostname: admitted(job.targetId).hostname }); audit('project.clone.cancel', id); return job;
    },
  };
}
