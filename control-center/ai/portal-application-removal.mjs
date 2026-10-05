const PROJECT_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;

function portalRemovalError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

export function publicPortalRemovalError(error) {
  if (error?.code !== 'PORTAL_APPLICATION_REAUTH_REQUIRED') return null;
  return { available: false, error: error.code, message: 'Riautenticati con la passkey e ripeti la richiesta: serve una sessione proprietario recente.', mutationPerformed: false };
}

const normalize = value => String(value || '').normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim();
const escapeRegex = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
function mentions(text, identity) {
  const pattern = escapeRegex(normalize(identity)).replace(/ /g, '\\s+');
  return pattern && new RegExp(`(^|[^a-z0-9-])${pattern}(?=$|[^a-z0-9-])`).test(text);
}
function identities(project) { return [project.slug, project.name].filter(value => typeof value === 'string' && value.trim()); }

export function authorizesPortalApplicationRemoval(message, project, projects) {
  if (typeof message !== 'string' || message.length > 32768 || !PROJECT_ID.test(project?.slug || '') || !Array.isArray(projects)) return false;
  const text = normalize(message);
  if (/^["'`>]/.test(text) || text.includes('?') || /\b(?:non|senza|evita|vietato|don't|do not|never)\b/.test(text)) return false;
  const clause = text.split(/[;.!\n]/, 1)[0];
  if (!/^(?:(?:per favore|please),?\s+)?(?:rimuovi|elimina|togli|remove|delete)\b/.test(clause)) return false;
  if (!/\b(?:app|applicazione|applicazioni|application|applications)\b/.test(clause)) return false;
    const mentioned = projects.filter(candidate => identities(candidate).some(identity => mentions(clause, identity)));
  return mentioned.length === 1 && mentioned[0].slug === project.slug;
}

export function createPortalApplicationRemoval({ authorize, getContext, applyDelete, invalidate, verify, machineId }) {
  if (![authorize, getContext, applyDelete, invalidate, verify].every(value => typeof value === 'function') || !/^[a-f0-9]{64}$/.test(machineId || '')) throw new Error('Invalid portal application removal wiring');
  return async function removePortalApplication(args, context) {
    const requested = args?.application;
    if (!args || Object.getPrototypeOf(args) !== Object.prototype || Object.keys(args).length !== 1 || typeof requested !== 'string' || !requested.trim() || requested.length > 160) throw new Error('Applicazione non valida.');
    if (context?.projectScope !== 'machine' || context.projectId || context.machineId !== machineId || context.role !== 'owner' || context.automaticContinuation) throw new Error('Operazione disponibile solo al proprietario nella chat Server generale.');
    const current = await getContext();
    const projects = Array.isArray(current.projects) ? current.projects : [];
    const matches = projects.filter(project => identities(project).some(identity => normalize(identity) === normalize(requested)));
    if (matches.length !== 1) throw new Error('Applicazione assente o ambigua nella lista del portale.');
    const project = matches[0];
    if (!authorizesPortalApplicationRemoval(context.latestUserMessage, project, projects)) throw new Error('Specifica nel messaggio corrente di rimuovere dalla lista Applicazioni una sola voce con il suo nome o ID esatto.');
    if (!await authorize({ subject: context.subject, role: context.role, change: true, sessionTokenHash: context.sessionTokenHash })) throw portalRemovalError('PORTAL_APPLICATION_REAUTH_REQUIRED', 'Riautenticati con la passkey e ripeti la richiesta: serve una sessione proprietario recente.');
    const operation = applyDelete(project.slug, { confirm: `REMOVE-FROM-LIST:${project.slug}` }, current);
    let confirmed = false;
    try { await invalidate(); confirmed = await verify(project.slug) === true; }
    catch { confirmed = false; }
    return { removedFromPortal: confirmed, status: confirmed ? 'removed' : 'reconciliation_required', projectId: project.slug, operationId: operation.id, filesystemTouched: false, databaseTouched: false, dockerTouched: false };
  };
}
