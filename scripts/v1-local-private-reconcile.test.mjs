import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const reconciler = path.join(here, "v1-local-private-reconcile.py");
const source = fs.readFileSync(reconciler, "utf8");
const python = process.env.PLATFORM_TEST_PYTHON || "/usr/bin/python3";

function runPython(body) {
  return execFileSync(python, ["-c", `import json,runpy\nm=runpy.run_path(${JSON.stringify(reconciler)},run_name='v1_reconciler_test')\n${body}`], {
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function jsonPython(body) {
  return JSON.parse(runPython(body));
}

test("closed V1 cardinalities, dependency order, images, artifacts and CLI remain exact", () => {
  const value = jsonPython(`
print(json.dumps({
 'active': list(m['ACTIVE_MANAGED']),
 'canonical': list(m['CANONICAL_CONTAINERS']),
 'disabled': list(m['DISABLED_SERVICES']),
 'images': [item[0] for item in m['LOCAL_IMAGE_BUILDS']],
 'order': list(m['SERVICE_REFRESH_ORDER']),
 'preserved': list(m['PRESERVED_LEGACY']),
 'secretRoot': m['SECRET_DIR'],
 'sudoers': m['SUDOERS'],
},sort_keys=True))`);
  assert.equal(value.canonical.length, 36);
  assert.equal(value.active.length, 17);
  assert.equal(value.preserved.length, 19);
  assert.deepEqual(value.disabled, ["backup-scheduler", "docker-action-activation-sidecar", "docker-action-broker"]);
  assert.deepEqual(new Set(value.order), new Set(value.active));
  assert.deepEqual(value.images, [
    "CONTROL_CENTER_IMAGE",
    "PLATFORM_ALERT_DISPATCHER_IMAGE",
    "PLATFORM_OPS_IMAGE",
    "PROJECT_ROUTER_IMAGE",
  ]);
  assert.equal(value.secretRoot, "/home/platform_infrastructure/platform-infrastructure/secrets");
  assert.equal(value.sudoers, "/etc/sudoers.d/platform-v1-local-private-control");
  assert.deepEqual(jsonPython(`print(json.dumps([item[0] for item in m['BACKUP_TOOL_IMAGE_ENV']]))`), [
    "mariadbRestore", "minioRestore", "nodeUtility", "postgresRestore", "resticRclone",
  ]);
  assert.doesNotMatch(source, /\bV2\b/);
  assert.doesNotMatch(source, /backupToolImage(?!s)/);
  assert.match(source, /prepare\|apply\|abort\|evidence/);
  assert.match(source, /"composeWrapper", "controller", "installer", "reconciler", "sudoers", "unit"/);
});

test("runtime identity is two-pass, non-circular and every excluded container is explicitly LEGACY_UNMANAGED", () => {
  const value = jsonPython(`
import copy,os,tempfile
root=tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root,0o700)
g=m['runtime_identity_environment'].__globals__; g['TEST_ROOT']=root; g['OWNER_UID']=os.geteuid(); g['OWNER_GID']=os.stat(root).st_gid
commit='1'*40; tree='2'*40; archive='3'*64; release=m['release_root'](commit,archive)
lock_path=m['physical'](f'{release}/config/no-hosted-workloads.local-private.lock.json')
os.makedirs(os.path.dirname(lock_path),mode=0o700,exist_ok=True); open(lock_path,'wb').write(b'{"state":"verified"}\\n'); os.chmod(lock_path,0o444)
source_render={'name':'platform_infra_vps','services':{service:{'image':'registry.invalid/'+service+'@sha256:'+'4'*64} for service in m['MANAGED_CONTAINER_BY_SERVICE']}}
source_bytes=m['canonical_bytes'](source_render); runtime=m['runtime_identity_environment'](commit,tree,release,source_bytes)
document=m['runtime_identity_document'](runtime); final=copy.deepcopy(source_render); labels=m['runtime_identity_labels'](document)
for service in final['services'].values(): service['labels']=dict(labels)
m['validate_runtime_identity_document'](document,commit,tree,release,final,runtime)
bad_label=copy.deepcopy(final); del bad_label['services']['postgres']['labels']['com.platform.runtime.commit']
label_rejected=False
try: m['validate_runtime_identity_document'](document,commit,tree,release,bad_label,runtime)
except m['Stop']: label_rejected=True
bad_document=dict(document); bad_document['sourceRenderSha256']='0'*64
source_rejected=False
try: m['validate_runtime_identity_document'](bad_document,commit,tree,release,final,runtime)
except m['Stop']: source_rejected=True
print(json.dumps({'activeServices':len(final['services']),'candidateDerived':document['candidateId']==m['digest'](m['canonical']({
 'candidateCommit':commit,'candidateTree':tree,'sourceRenderSha256':m['digest'](source_bytes),
 'workloadLockSha256':m['digest'](b'{"state":"verified"}\\n')}).encode()),
 'identityProjection':m['source_render_without_runtime_identity'](final)==source_bytes,
 'labelRejected':label_rejected,'legacy':list(m['LEGACY_UNMANAGED']),'sourceRejected':source_rejected}))`);
  assert.equal(value.activeServices, 20, "source/final render contains 17 active plus 3 backup-profile services");
  assert.equal(value.candidateDerived, true);
  assert.equal(value.identityProjection, true);
  assert.equal(value.labelRejected, true);
  assert.equal(value.sourceRejected, true);
  assert.equal(value.legacy.length, 19);
  assert.deepEqual(value.legacy.map((item) => item.containerName), [...value.legacy.map((item) => item.containerName)].sort());
  assert.ok(value.legacy.every((item) => item.status === "LEGACY_UNMANAGED"));
  assert.equal(value.legacy.find((item) => item.containerName === "php-apache").reason, "COMPOSE_PROFILE_LEGACY_SHARED_RUNTIME_DISABLED");
  assert.equal(value.legacy.find((item) => item.containerName === "phpmyadmin").reason, "COMPOSE_PROFILE_ADMIN_DISABLED");
  assert.equal(value.legacy.find((item) => item.containerName === "enterprise-backend").reason, "NO_HOSTED_WORKLOAD_AUTHORITY");
});

test("managed target requires exact Compose hash and live runtime envelope, not a brownfield subset", () => {
  const value = jsonPython(`
import copy
runtime_labels={name:value for name,value in zip(sorted(m['RUNTIME_IDENTITY_LABEL_BY_ENV'].values()),('a','b','c','d','e','f'))}
config_hash='7'*64; identifier='8'*64; image='sha256:'+'9'*64; name='enterprise-control-center'
raw={
 'Id':identifier,'Image':image,'Name':'/'+name,'Mounts':[],
 'Config':{'Cmd':None,'Entrypoint':None,'Env':[],'Healthcheck':None,'Image':'registry.invalid/control@'+image,
  'Labels':{**runtime_labels,'com.docker.compose.config-hash':config_hash,'com.docker.compose.project':'platform_infra_vps',
   'traefik.enable':'false',
   'com.docker.compose.service':'control-center'},'User':'','WorkingDir':'/app'},
 'HostConfig':{'BlkioWeight':700,'CapAdd':None,'CapDrop':None,'CpuShares':1024,'ExtraHosts':['auth.local:host-gateway'],
  'GroupAdd':['100'],'Init':True,'Memory':536870912,'MemoryReservation':134217728,'NanoCpus':1000000000,
  'LogConfig':{'Type':'json-file','Config':{'max-file':'5','max-size':'10m'}},
  'NetworkMode':'platform_infra_vps_platform_routing','PidMode':'','PidsLimit':384,'PortBindings':{},'Privileged':False,
  'ReadonlyRootfs':True,'RestartPolicy':{'Name':'always'},'SecurityOpt':['no-new-privileges:true'],
  'Tmpfs':{'/tmp':'rw,noexec,nosuid,nodev,size=67108864'},'Ulimits':[{'Name':'nofile','Soft':16384,'Hard':16384}]},
 'NetworkSettings':{'Networks':{'platform_infra_vps_platform_routing':{'Aliases':[name,identifier[:12]]}},'Ports':{}},
 'State':{'ExitCode':0,'Health':{'Status':'healthy'},'Status':'running'},
}
identity=m['container_identity'](raw); semantic=m['inspect_service_semantics'](raw,name)
target={'configHash':config_hash,'containerName':name,'project':'platform_infra_vps','semantic':semantic,'service':'control-center'}
baseline=m['target_semantics'](name,target,raw,identity)
wrong_hash=dict(target); wrong_hash['configHash']='0'*64
memory_drift=copy.deepcopy(raw); memory_drift['HostConfig']['Memory']=268435456
label_drift=copy.deepcopy(raw); del label_drift['Config']['Labels']['com.platform.runtime.commit']
routing_drift=copy.deepcopy(raw); routing_drift['Config']['Labels']['traefik.enable']='true'
print(json.dumps({'baseline':baseline,'hashRejected':not m['target_semantics'](name,wrong_hash,raw,identity),
 'labelRejected':m['inspect_service_semantics'](label_drift,name)!=semantic,
 'memoryRejected':m['inspect_service_semantics'](memory_drift,name)!=semantic,
 'routingRejected':m['inspect_service_semantics'](routing_drift,name)!=semantic,
 'fields':sorted(semantic)}))`);
  assert.equal(value.baseline, true);
  assert.equal(value.hashRejected, true);
  assert.equal(value.labelRejected, true);
  assert.equal(value.memoryRejected, true);
  assert.equal(value.routingRejected, true);
  for (const field of ["blkioWeight", "cpuShares", "extraHosts", "groupAdd", "logging", "memoryBytes", "memoryReservationBytes", "nanoCpus", "networkEndpoints", "pidMode", "routingLabels", "runtimeIdentityLabels", "tmpfs", "ulimits", "workingDirectory"]) {
    assert.ok(value.fields.includes(field), `missing exact runtime field ${field}`);
  }
});

test("managed network semantics bind Compose default and explicit endpoint aliases", () => {
  const value = jsonPython(`
identifier='1'*64; container='enterprise-mariadb'; service='mariadb'; project='platform_infra_vps'
render={'networks':{'db_admin':{'name':'platform_infra_vps_db_admin'}},'services':{service:{
 'container_name':container,'networks':{'db_admin':{'aliases':['platform.local']}}
}}}
mode,names,expected=m['render_networks'](render,service,render['services'][service],project,'mariadb')
raw={'Id':identifier,'NetworkSettings':{'Networks':{'platform_infra_vps_db_admin':{
 'Aliases':[identifier[:12],container,service,'platform.local']}}}}
observed=m['inspect_network_membership'](raw,container)
drift={'Id':identifier,'NetworkSettings':{'Networks':{'platform_infra_vps_db_admin':{
 'Aliases':[identifier[:12],container,service]}}}}
print(json.dumps({'driftRejected':m['inspect_network_membership'](drift,container)!=expected,
 'expected':expected,'mode':mode,'names':names,'observed':observed},sort_keys=True))`);
  assert.equal(value.mode, "managed");
  assert.deepEqual(value.names, ["platform_infra_vps_db_admin"]);
  assert.deepEqual(value.expected, [{
    aliases: ["enterprise-mariadb", "mariadb", "platform.local"],
    networkName: "platform_infra_vps_db_admin",
  }]);
  assert.deepEqual(value.observed, value.expected);
  assert.equal(value.driftRejected, true);
});

test("apply reopens the exact fresh PRE checkpoint, five evidence files and recovery export before mutation", () => {
  const value = jsonPython(`
import os,tempfile,time,copy
g=m['validate_pre_mutation_checkpoint'].__globals__; g['OWNER_UID']=os.geteuid()
def put(logical,value,mode=0o400,raw=False):
 p=m['physical'](logical); os.makedirs(os.path.dirname(p),mode=0o700,exist_ok=True)
 if os.path.exists(p): os.chmod(p,0o600)
 data=value if raw else m['canonical_bytes'](value)
 with open(p,'wb') as stream: stream.write(data)
 os.chmod(p,mode); return data
def scenario(kind):
 root=tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root,0o700)
 g['TEST_ROOT']=root; g['OWNER_GID']=os.stat(root).st_gid
 now=int(time.time()); generated=now-901 if kind=='stale' else now-5; captured=generated-20
 checkpoint_generated=generated+1 if kind=='crossedSecond' else generated
 commit='1'*40; tree='2'*40; archive='3'*64; doc='4'*64
 tools={name:{'imageId':'sha256:'+'5'*64,'imageReference':'registry.invalid/'+name+'@sha256:'+'6'*64} for name in ('mariadbRestore','minioRestore','nodeUtility','postgresRestore','resticRclone')}
 authority={'backupToolImages':tools,'candidateCommit':commit,'candidateTree':tree,'documentId':doc,'sourceArchiveSha256':archive}
 authority_bytes=m['canonical_bytes'](authority)
 common={'artifactSetSha256':'7'*64,'authorityDocumentId':('0'*64 if kind=='authority' else doc),
  'authoritySha256':m['digest'](authority_bytes),'backupSetSha256':'8'*64,'backupToolImages':tools,
  'candidateCommit':commit,'candidateTree':tree,'evidencePhase':'PRE','reconciliationSha256':None,
  'runId':'20260824T120000Z-abcdef12','sourceArchiveSha256':archive,'transactionId':None}
 logical={**common,'artifactCount':14,'artifactManifestSha256':'9'*64,'artifacts':[],'backupCompletedUnixSeconds':captured,
  'capturedAtUnixSeconds':captured,'checksumVerifiedCount':14,'freshArtifactStreamHashCount':14,
  'generatedAtUnixSeconds':generated,'hmacVerifiedCount':14,'schema':'platform.v1-local-private-logical-backup-evidence/v1',
  'sourceSummarySha256':'a'*64,'status':'PASS','totalArtifactBytes':14}
 offhost={**common,'artifactCount':14,'completedAtUnixSeconds':generated-1,'distinctSnapshotCount':14,
  'exactPayloadReadbackCount':14,'freshExactSnapshotCount':14,'generatedAtUnixSeconds':generated,'hostingerUsed':False,
  'noPrune':True,'offsiteProofSha256':'b'*64,'proofs':[],'recoveryEscrow':{},
  'repository':'rclone:platform-onedrive:platform-infrastructure/restic','repositoryProvider':'OneDrive','retentionSkipped':True,
  'schema':'platform.v1-local-private-offhost-backup-evidence/v1','sourceSummarySha256':'a'*64,'status':'PASS'}
 restore={**common,'artifactCount':14,'completedAtUnixSeconds':generated-1,'expectedRestoreCount':14,
  'generatedAtUnixSeconds':generated,'localRestoreResultsSha256':'c'*64,'passedRestoreCount':14,'results':[],
  'schema':'platform.v1-local-private-restore-evidence/v1','sourceSummarySha256':'a'*64,'status':'PASS'}
 secret={**common,'backupCompletedUnixSeconds':captured,'capturedAtUnixSeconds':captured,'encryptedArtifact':{},
  'generatedAtUnixSeconds':generated,'plaintextTemporaryStateAbsent':True,'recoveryEscrow':{},
  'schema':'platform.v1-local-private-secrets-backup-evidence/v1','secretBindingInventory':{},'secretRestore':{},
  'secretValuesRecorded':False,'sourceSummarySha256':'a'*64,'status':'PASS'}
 export_data=b'x'*2048; put(m['SCHEDULER_RECOVERY_EXPORT'],export_data,raw=True)
 export_snapshot=m['stable_recovery_export_snapshot'](); recovery_id='sha256:'+'d'*64; running_id='sha256:'+'e'*64
 runtime={**common,'capturedAtUnixSeconds':generated,'containerCount':36,'containerIdentitySetSha256':'f'*64,
  'generatedAtUnixSeconds':generated,'recovery':{'exportSha256':export_snapshot['sha256'],'recoveryImageId':recovery_id,
  'runningImageId':running_id},'schema':'platform.v1-local-private-runtime-inventory-evidence/v1','status':'PASS',
  'volumeCount':1,'volumeSetSha256':'1'*64}
 documents={'logicalBackupEvidenceSha256':logical,'offHostBackupEvidenceSha256':offhost,
  'restoreEvidenceSha256':restore,'runtimeInventorySha256':runtime,'secretsBackupEvidenceSha256':secret}
 digests={key:m['digest'](put(m['CHECKPOINT_EVIDENCE_PATHS'][key],document)) for key,document in documents.items()}
 checkpoint={'authoritative':False,'backupCapturedUnixSeconds':captured,'candidateCommit':commit,'candidateTree':tree,
  'destructiveMutationPlanned':False,'generatedAtUnixSeconds':checkpoint_generated,**digests,'restoreVerified':True,'runtimeRecovered':True,
  'schedulerRecoveryImageExportSha256':export_snapshot['sha256'],'schedulerRecoveryImageId':recovery_id,
  'schedulerRunningImageId':running_id,'schema':'platform.v1-local-private-predeploy-checkpoint/v1','sourceArchiveSha256':archive}
 checkpoint_bytes=put(m['LOCAL_CHECKPOINT'],checkpoint)
 labels={'com.platform.v1.local-private.candidate-commit':commit,
  'com.platform.v1.local-private.scheduler-config-hash':'2'*64,
  'com.platform.v1.local-private.scheduler-container-id':'3'*64,
  'com.platform.v1.local-private.scheduler-running-image-id':running_id}
 config='sha256:'+'4'*64
 recovery={'archiveFormat':'OCI_DOCKER_SAVE_V1','configDigest':config,'configHash':'2'*64,'containerId':'3'*64,
  'exportIdentity':export_snapshot['identity'],'exportLabels':labels,'exportPath':m['SCHEDULER_RECOVERY_EXPORT'],
  'exportSha256':export_snapshot['sha256'],'exportSizeBytes':export_snapshot['sizeBytes'],'imageIndexDigest':recovery_id,
  'imageIndexPath':'blobs/sha256/'+recovery_id.removeprefix('sha256:'),'imageManifestDigest':'sha256:'+'5'*64,
  'manifestConfig':'blobs/sha256/'+config.removeprefix('sha256:'),'recoveryImageId':recovery_id,
  'recoveryTag':'platform/v1-scheduler-recovery:'+commit,'runningImageId':running_id}
 reconciliation={'rollbackCheckpointSha256':m['digest'](checkpoint_bytes),'rollbackSchedulerRecovery':recovery,
  'rollbackSchedulerRecoverySha256':m['digest'](m['canonical'](recovery).encode())}
 if kind=='checkpoint':
  bad=dict(checkpoint); bad['generatedAtUnixSeconds']=generated-1; put(m['LOCAL_CHECKPOINT'],bad)
 elif kind=='evidence':
  bad=dict(logical); bad['status']='FAIL'; put(m['CHECKPOINT_EVIDENCE_PATHS']['logicalBackupEvidenceSha256'],bad)
 elif kind=='export': put(m['SCHEDULER_RECOVERY_EXPORT'],b'y'*2048,raw=True)
 elif kind=='recovery':
  reconciliation['rollbackSchedulerRecovery']=dict(recovery); reconciliation['rollbackSchedulerRecovery']['configHash']='6'*64
  reconciliation['rollbackSchedulerRecoverySha256']=m['digest'](m['canonical'](reconciliation['rollbackSchedulerRecovery']).encode())
 try:
  m['validate_pre_mutation_checkpoint'](authority,authority_bytes,reconciliation); return True
 except m['Stop']: return False
results={kind:scenario(kind) for kind in ('baseline','crossedSecond','stale','checkpoint','evidence','authority','export','recovery')}
calls=[]
g=m['apply'].__globals__
spy_authority={'documentId':'4'*64}; spy_authority_bytes=m['canonical_bytes'](spy_authority); spy_reconciliation={}
g['require_maintenance_ready']=lambda:calls.append('maintenance')
g['read_authority']=lambda:(spy_authority,spy_authority_bytes)
g['validate_authority_material']=lambda value:{}
g['read_reconciliation']=lambda value,data:spy_reconciliation
def reject_guard(*args): calls.append('guard'); raise m['Stop']('rejected')
g['validate_pre_mutation_checkpoint']=reject_guard
for name in ('configure_secret_anchor','read_or_create_journal','promote_live_environment'):
 g[name]=lambda *args,n=name:calls.append(n)
try: m['apply']()
except m['Stop']: pass
print(json.dumps({'calls':calls,'results':results},sort_keys=True))`);
  assert.deepEqual(value.results, {
    authority: false,
    baseline: true,
    checkpoint: false,
    crossedSecond: true,
    evidence: false,
    export: false,
    recovery: false,
    stale: false,
  });
  assert.deepEqual(value.calls, ["maintenance", "guard"]);
  const applySource = runPython("import inspect; print(inspect.getsource(m['apply']))");
  assert.match(applySource, /validate_pre_mutation_checkpoint[\s\S]*configure_secret_anchor[\s\S]*read_or_create_journal[\s\S]*promote_live_environment/);
});

test("legacy compatibility authority is the proven routing/dependency matrix", () => {
  const value = jsonPython(`
names=('routing','db_admin','postgres','cache','bus','storage','observability','egress')
render={'networks': {'platform_'+name:{'name':'platform_infra_vps_'+name} for name in names}}
attachments,routes=m['route_contract'](render,{'DOMAIN':'platform-infrastructure.com'})
print(json.dumps({'attachments':attachments,'routes':routes},sort_keys=True))`);
  const signature = new Set(value.attachments.map((item) => `${item.containerName}|${item.networkName}|${item.aliases.join(",")}`));
  const expected = [
    ["enterprise-backend", "postgres", "backend"], ["enterprise-backend", "cache", "backend"],
    ["enterprise-backend", "bus", "backend"], ["enterprise-backend", "storage", "backend"],
    ["enterprise-backend", "egress", "backend"],
    ["enterprise-cadvisor", "observability", "cadvisor"],
    ["enterprise-node-exporter", "observability", "node-exporter"],
    ["enterprise-worker-jobs", "postgres", "worker-jobs"], ["enterprise-worker-jobs", "cache", "worker-jobs"],
    ["enterprise-worker-jobs", "bus", "worker-jobs"],
    ["enterprise-worker-notifications", "postgres", "worker-notifications"],
    ["enterprise-worker-notifications", "cache", "worker-notifications"],
    ["enterprise-worker-notifications", "bus", "worker-notifications"],
    ["enterprise-worker-notifications", "observability", "worker-notifications"],
    ["enterprise-worker-notifications", "egress", "worker-notifications"],
    ["node-account", "routing", "node-account"], ["node-opstudents", "routing", "node-opstudents"],
    ["node-ui", "routing", "node-ui"],
    ["php-anniversary", "routing", "php-anniversary"], ["php-anniversary", "db_admin", "php-anniversary"],
    ["php-fiplatform", "routing", "php-fiplatform"], ["php-fiplatform", "db_admin", "php-fiplatform"],
    ["php-matthewdifilippo", "routing", "php-matthewdifilippo"],
    ["php-stream", "routing", "php-stream"], ["php-stream", "db_admin", "php-stream"],
    ["php-workcalendar", "routing", "php-workcalendar"], ["php-workcalendar", "db_admin", "php-workcalendar"],
    ["phpmyadmin", "routing", "phpmyadmin"], ["phpmyadmin", "db_admin", "phpmyadmin"],
    ["phppgadmin", "db_admin", "phppgadmin"],
  ].map(([container, zone, alias]) => `${container}|platform_infra_vps_${zone}|${alias}`);
  assert.deepEqual(signature, new Set(expected));
  assert.equal(value.routes.length, 10);
  assert.deepEqual(value.routes.map((item) => item.name), [...value.routes.map((item) => item.name)].sort());
  assert.deepEqual(
    value.routes.map(({ containerName, expectedStatus, name, url }) => ({ containerName, expectedStatus, name, url })),
    [
      ["account", "node-account", 200], ["anniversary", "php-anniversary", 200],
      ["fiplatform", "php-fiplatform", 200], ["fireport", "php-fiplatform", 200],
      ["matthewdifilippo", "php-matthewdifilippo", 200], ["opstudents", "node-opstudents", 200],
      ["stream", "php-stream", 303], ["ui", "node-ui", 200], ["workcalendar", "php-workcalendar", 302],
    ].map(([slug, containerName, expectedStatus]) => ({
      containerName, expectedStatus, name: `${slug}-edge-route`, url: `https://${slug}.platform-infrastructure.com/`,
    })).concat([{ containerName: "phpmyadmin", expectedStatus: 200, name: "phpmyadmin-portal-route", url: "https://portal.platform-infrastructure.com/phpmyadmin" }]).sort((a, b) => a.name.localeCompare(b.name)),
  );
  const routed = new Set(value.attachments.filter((item) => item.networkName.endsWith("_routing")).map((item) => item.containerName));
  const checked = new Set(value.routes.map((item) => item.containerName));
  for (const container of routed) assert.ok(checked.has(container), `missing route proof for ${container}`);
});

test("bounded subprocess input works and sensitive failures suppress command output", () => {
  const value = jsonPython(`
r=m['run_result'](['/bin/sh','-c','IFS= read -r value; test "x$value" = xhello'],'input test',input_bytes=b'hello\\n')
message=''
try:
 m['run'](['/bin/sh','-c','echo SECRET_CANARY >&2; exit 9'],'sensitive failure',sensitive=True)
except m['Stop'] as error:
 message=str(error)
print(json.dumps({'returncode':r.returncode,'message':message}))`);
  assert.equal(value.returncode, 0);
  assert.match(value.message, /output was suppressed/);
  assert.doesNotMatch(value.message, /SECRET_CANARY/);
});

test("prepare is checkpoint/staging-bound and Git cannot execute caller or repository hooks", () => {
  const prepareSource = runPython("import inspect; print(inspect.getsource(m['prepare']))");
  const gitSource = runPython("import inspect; print(inspect.getsource(m['git_output'])+inspect.getsource(m['git_archive']))");
  const envSource = runPython("import inspect; print(inspect.getsource(m['update_deployment_environment']))");
  assert.match(prepareSource, /install_binding\(\)/);
  assert.match(prepareSource, /\.v1-release-staging/);
  assert.doesNotMatch(prepareSource, /os\.getcwd\(\)/);
  assert.doesNotMatch(prepareSource, /configure_secret_anchor|ensure_secret_directory|DEPLOYMENT_REPO.*\.env/);
  assert.match(runPython("import inspect; print(inspect.getsource(m['apply']))"), /configure_secret_anchor\(\)[\s\S]*promote_live_environment\(\)/);
  assert.match(gitSource, /GIT_CONFIG_GLOBAL/);
  assert.match(gitSource, /GIT_CONFIG_NOSYSTEM/);
  assert.match(gitSource, /core\.fsmonitor=false/);
  assert.match(gitSource, /core\.hooksPath=\/dev\/null/);
  assert.match(gitSource, /safe\.directory=/);
  assert.match(envSource, /stat\.S_IMODE\(info\.st_mode\) not in \(0o400, 0o600\)/);
  assert.match(envSource, /current\.st_dev, current\.st_ino, current\.st_size, current\.st_mtime_ns/);
  assert.match(envSource, /set\(replacements\).*LOCAL_IMAGE_BUILDS/);
  assert.match(prepareSource, /recovery_escrow_certificate_binding\(release\)[\s\S]*provision_confidential_backup_passphrase\(\)[\s\S]*materialize_environment/);
});

test("prepare install binding accepts only the fresh non-authoritative transport checkpoint", () => {
  const value = jsonPython(`
import copy,os,tempfile,time
root=tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root,0o700)
g=m['install_binding'].__globals__; g['TEST_ROOT']=root; g['OWNER_UID']=os.geteuid(); g['OWNER_GID']=os.stat(root).st_gid
commit='1'*40; tree='2'*40; archive_bytes=b'x'*2048; archive_sha=m['digest'](archive_bytes); release=m['release_root'](commit,archive_sha)
checkpoint={
 'activationAuthorized':False,'authoritative':False,'backupEvidenceAuthoritative':False,
 'bridgeSha256':'3'*64,'candidateCommit':commit,'candidateConsumerSha256':'4'*64,
 'candidateTree':tree,'createdAtUnixSeconds':int(time.time()),'gitBundleSha256':'5'*64,
 'purpose':'CONTROL_PLANE_STAGING_ONLY','schema':'platform.v1-bootstrap-transport-checkpoint/v1',
 'sourceArchiveSha256':archive_sha,'sourceArchiveSizeBytes':len(archive_bytes),'transportVerified':True,
}
receipt={
 'activationAuthorized':False,'authorizationSource':'ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY',
 'backupEvidenceAuthoritative':False,'candidateCommit':commit,'candidateTree':tree,
 'dataMutation':False,'dockerMutation':False,
 'readyButDisabled':['PROVIDER_ADMISSION','DNS_PUBLICATION','DAST','SIGSTORE_PROMOTION','DOCKER_CONTROL_PLANE'],
 'releaseRoot':release,'schema':'platform.v1-brownfield-install-receipt/v1',
 'sourceArchiveSha256':archive_sha,'status':'INSTALL_ONLY_COMPLETE',
}
def put(logical,data,mode=0o400):
 pathname=m['physical'](logical); os.makedirs(os.path.dirname(pathname),mode=0o700,exist_ok=True)
 if os.path.exists(pathname): os.chmod(pathname,0o600)
 with open(pathname,'wb') as target: target.write(data)
 os.chmod(pathname,mode)
def checkpoint_result(candidate):
 put(m['INSTALL_CHECKPOINT'],m['canonical_bytes'](candidate))
 try: return {'accepted':True,'binding':m['install_binding']()}
 except m['Stop'] as error: return {'accepted':False,'message':str(error)}
put(m['SOURCE_ARCHIVE'],archive_bytes)
put(f'/var/lib/platform-infrastructure/v1/install-receipts/{commit}-{archive_sha}.json',m['canonical_bytes'](receipt))
accepted=checkpoint_result(checkpoint)
cases={}
for name,mutate in (
 ('historicalSchema',lambda item:item.update(schema='platform.v1-local-private-checkpoint/v1')),
 ('activationClaim',lambda item:item.update(activationAuthorized=True)),
 ('authorityClaim',lambda item:item.update(authoritative=True)),
 ('backupClaim',lambda item:item.update(backupEvidenceAuthoritative=True)),
 ('wrongPurpose',lambda item:item.update(purpose='CUTOVER')),
 ('unverified',lambda item:item.update(transportVerified=False)),
 ('stale',lambda item:item.update(createdAtUnixSeconds=int(time.time())-901)),
 ('sizeDrift',lambda item:item.update(sourceArchiveSizeBytes=len(archive_bytes)+1)),
 ('extraRestoreClaim',lambda item:item.update(restoreVerified=True)),
):
 candidate=copy.deepcopy(checkpoint); mutate(candidate); cases[name]=checkpoint_result(candidate)
print(json.dumps({'accepted':accepted,'cases':cases},sort_keys=True))`);
  assert.equal(value.accepted.accepted, true);
  assert.deepEqual(value.accepted.binding, {
    candidateCommit: "1".repeat(40),
    candidateTree: "2".repeat(40),
    releaseRoot: value.accepted.binding.releaseRoot,
    sourceArchiveSha256: value.accepted.binding.sourceArchiveSha256,
  });
  assert.match(value.accepted.binding.releaseRoot, /^\/srv\/platform-infrastructure\/releases\/[a-f0-9]{40}-[a-f0-9]{64}$/);
  for (const [name, result] of Object.entries(value.cases)) {
    assert.equal(result.accepted, false, `${name} unexpectedly authorized prepare`);
    assert.match(result.message, /transport|closed V1 schema|source archive/i, name);
  }
});

test("confidential backup passphrase is exclusive, private, idempotent and only path-bound into render env", () => {
  const value = jsonPython(`
import os,stat,tempfile
root=tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root,0o700)
g=m['provision_confidential_backup_passphrase'].__globals__; g['TEST_ROOT']=root; g['OWNER_UID']=os.geteuid(); g['OWNER_GID']=os.stat(root).st_gid
m['provision_confidential_backup_passphrase'](); path=m['physical'](m['CONFIDENTIAL_BACKUP_PASSPHRASE'])
first=open(path,'rb').read(); identity=os.stat(path,follow_symlinks=False)
m['provision_confidential_backup_passphrase'](); second=open(path,'rb').read(); after=os.stat(path,follow_symlinks=False)
print(json.dumps({'idempotent':first==second and identity.st_ino==after.st_ino,'length':len(first),
 'mode':stat.S_IMODE(after.st_mode),'nlink':after.st_nlink,'newline':first.endswith(b'\\n')}))`);
  assert.equal(value.idempotent, true);
  assert.equal(value.mode, 0o400);
  assert.equal(value.nlink, 1);
  assert.equal(value.newline, true);
  assert.ok(value.length >= 65);
  assert.match(source, /V1_CONFIDENTIAL_BACKUP_PASSPHRASE_FILE.*CONFIDENTIAL_BACKUP_PASSPHRASE/);
  assert.doesNotMatch(source, /V1_CONFIDENTIAL_BACKUP_PASSPHRASE_FILE=.*token_urlsafe/);
});

test("confidential passphrase resumes every create/write/fsync/publish crash without rotation", () => {
  const value = jsonPython(`
import os,stat,tempfile
boundaries=('PASSPHRASE_AFTER_TEMP_CREATE','PASSPHRASE_AFTER_TEMP_WRITE','PASSPHRASE_AFTER_TEMP_FSYNC','PASSPHRASE_AFTER_PUBLISH')
results=[]; g=m['provision_confidential_backup_passphrase'].__globals__
for boundary in boundaries:
 root=tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root,0o700)
 g['TEST_ROOT']=root; g['OWNER_UID']=os.geteuid(); g['OWNER_GID']=os.stat(root).st_gid
 os.environ['PLATFORM_V1_RECONCILE_TEST_FAULT']=boundary
 stopped=False
 try: m['provision_confidential_backup_passphrase']()
 except m['Stop']: stopped=True
 finally: os.environ.pop('PLATFORM_V1_RECONCILE_TEST_FAULT',None)
 final=m['physical'](m['CONFIDENTIAL_BACKUP_PASSPHRASE']); staged=final+'.staging'; preserved=None
 for candidate in (final,staged):
  if os.path.exists(candidate) and os.path.getsize(candidate)>0: preserved=open(candidate,'rb').read(); break
 m['provision_confidential_backup_passphrase'](); info=os.stat(final,follow_symlinks=False); observed=open(final,'rb').read()
 results.append({'boundary':boundary,'stopped':stopped,'preserved':preserved is None or preserved==observed,
  'mode':stat.S_IMODE(info.st_mode),'nlink':info.st_nlink,'stagingAbsent':not os.path.exists(staged)})
print(json.dumps(results))`);
  assert.equal(value.length, 4);
  for (const result of value) {
    assert.equal(result.stopped, true, result.boundary);
    assert.equal(result.preserved, true, result.boundary);
    assert.equal(result.mode, 0o400, result.boundary);
    assert.equal(result.nlink, 1, result.boundary);
    assert.equal(result.stagingAbsent, true, result.boundary);
  }
});

test("shared transaction lease fails 75 before reconciler-local mutation", () => {
  const value = jsonPython(`
import os,tempfile
root=tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root,0o700)
g=m['acquire_lock'].__globals__; g['TEST_ROOT']=root
first=m['acquire_lock'](m['SHARED_LOCK'],'shared transaction')
read_fd,write_fd=os.pipe(); pid=os.fork()
if pid==0:
 os.close(read_fd); result={'code':0,'stopped':False}
 try:
  second=m['acquire_lock'](m['SHARED_LOCK'],'shared transaction'); os.close(second)
 except m['Stop'] as error:
  result={'code':error.code,'stopped':True}
 os.write(write_fd,m['canonical_bytes'](result)); os.close(write_fd); os._exit(0)
os.close(write_fd); child=os.read(read_fd,4096); os.close(read_fd); os.waitpid(pid,0); os.close(first)
print(child.decode())`);
  assert.deepEqual(value, { code: 75, stopped: true });
  const mainSource = runPython("import inspect; print(inspect.getsource(m['main']))");
  assert.ok(mainSource.indexOf("acquire_lock(SHARED_LOCK") < mainSource.indexOf("acquire_lock(LOCK"));
  assert.ok(mainSource.indexOf("acquire_lock(LOCK") < mainSource.indexOf("}[operation]()"));
});

test("FD4 executor admits only typed closed actions with one monotonic session run ID", () => {
  const value = jsonPython(`
import socket,threading
tools={name:{'imageId':'sha256:'+char*64,'imageReference':f'registry.invalid/{name}@sha256:{char*64}'} for name,char in zip(
 ('mariadbRestore','minioRestore','nodeUtility','postgresRestore','resticRclone'),'12345')}
authority={'backupToolImages':tools,'serviceTargets':[],'evidenceProducer':{
 'executor':'/usr/bin/python3','executorFlags':['-I'],'forbiddenResticOperations':['forget','prune'],'hostingerAllowed':False,
 'logicalKeys':list(m['EVIDENCE_LOGICAL_KEYS']),'offsiteRepository':'rclone:platform-onedrive:platform-infrastructure/restic',
 'operations':['pre','post'],'path':'/release/producer.py','recoveryEscrowPrefix':'platform-onedrive:platform-infrastructure/key-escrow','sha256':'a'*64}}
def accepted(request,expected=1):
 try: m['validate_executor_request'](authority,request,expected); return True
 except m['Stop']: return False
run='20260824T120000Z-a1b2c3d4'
requests=[
 {'action':'RUNTIME_INVENTORY','id':1,'parameters':{'runId':run}},
 {'action':'VERIFY_TOOL_IMAGE','id':2,'parameters':{'runId':run,'tool':'resticRclone'}},
 {'action':'BACKUP_APPLICATIONS','id':3,'parameters':{'runId':run}},
 {'action':'BACKUP_POSTGRES','id':4,'parameters':{'database':'stexor','runId':run}},
 {'action':'BACKUP_MARIADB','id':5,'parameters':{'runId':run}},
 {'action':'BACKUP_MINIO','id':6,'parameters':{'runId':run}},
 {'action':'BACKUP_KEYCLOAK','id':7,'parameters':{'runId':run}},
 {'action':'BACKUP_SECRET_METADATA','id':8,'parameters':{'runId':run}},
 {'action':'RESTORE_POSTGRES','id':9,'parameters':{'logicalKey':'pg-keycloak','runId':run}},
 {'action':'RESTORE_MARIADB','id':10,'parameters':{'runId':run}},
 {'action':'RESTORE_MINIO','id':11,'parameters':{'runId':run}},
 {'action':'RESTORE_KEYCLOAK','id':12,'parameters':{'runId':run}},
 {'action':'RESTIC_SNAPSHOTS','id':13,'parameters':{'logicalKey':'stream','runId':run}},
 {'action':'RESTIC_BACKUP','id':14,'parameters':{'logicalKey':'confidential','runId':run}},
 {'action':'RESTIC_RESTORE','id':15,'parameters':{'logicalKey':'minio','runId':run,'snapshotId':'f'*64}},
 {'action':'ESCROW_UPLOAD','id':16,'parameters':{'runId':run}},
 {'action':'ESCROW_READBACK','id':17,'parameters':{'runId':run}},
]
denied={
 'foreignAction':not accepted({'action':'GENERIC','id':1,'parameters':{'runId':run}}),
 'rawArgv':not accepted({'action':'BACKUP_POSTGRES','arguments':['system','prune'],'id':1,'parameters':{'database':'stexor','runId':run}}),
 'destructiveRestic':not accepted({'action':'RESTIC_FORGET','id':1,'parameters':{'logicalKey':'stream','runId':run}}),
 'missingRun':not accepted({'action':'RUNTIME_INVENTORY','id':1,'parameters':{}}),
 'foreignLogicalKey':not accepted({'action':'RESTORE_POSTGRES','id':1,'parameters':{'logicalKey':'stream','runId':run}}),
 'idGap':not accepted(requests[1],1),
}
calls=[]; errors=[]
class Child:
 def __init__(self): self.terminated=False
 def poll(self): return None if not self.terminated else -15
 def terminate(self): self.terminated=True
child=Child(); g=m['serve_evidence_executor'].__globals__; original=g['execute_typed_evidence_action']
g['execute_typed_evidence_action']=lambda authority,action,parameters: calls.append([action,parameters['runId']]) or (0,m['canonical_bytes']({'status':'PASS'}),b'')
server,client=socket.socketpair(); thread=threading.Thread(target=m['serve_evidence_executor'],args=(server,authority,errors,child)); thread.start()
client.sendall(m['canonical_bytes'](requests[0])+m['canonical_bytes'](requests[1])+m['canonical_bytes']({
 'action':'BACKUP_APPLICATIONS','id':3,'parameters':{'runId':'20260824T120001Z-deadbeef'}}))
responses=b''
while responses.count(b'\\n') < 2:
 chunk=client.recv(65536)
 if not chunk: break
 responses+=chunk
client.close(); thread.join(2); g['execute_typed_evidence_action']=original
print(json.dumps({'accepted':[accepted(request,index) for index,request in enumerate(requests,1)],
 'denied':denied,'serverCalls':len(calls),'serverError':len(errors),'terminated':child.terminated,'threadAlive':thread.is_alive()}))`);
  assert.equal(value.accepted.length, 17);
  assert.ok(value.accepted.every(Boolean));
  assert.deepEqual(value.denied, {
    destructiveRestic: true,
    foreignLogicalKey: true,
    foreignAction: true,
    idGap: true,
    missingRun: true,
    rawArgv: true,
  });
  assert.equal(value.serverCalls, 2);
  assert.equal(value.serverError, 1);
  assert.equal(value.terminated, true);
  assert.equal(value.threadAlive, false);
  const invokeSource = runPython("import inspect; print(inspect.getsource(m['invoke_evidence_producer']))");
  assert.match(invokeSource, /socket\.socketpair/);
  assert.match(invokeSource, /PLATFORM_V1_EVIDENCE_EXECUTOR_FD.*4/);
  assert.match(invokeSource, /pass_fds=\(3, 4\)/);
  assert.doesNotMatch(invokeSource, /DOCKER_HOST/);
  const serverSource = runPython("import inspect; print(inspect.getsource(m['serve_evidence_executor']))");
  assert.ok(serverSource.indexOf("validate_executor_request") < serverSource.indexOf("execute_typed_evidence_action"));
  assert.doesNotMatch(serverSource, /arguments|infraOperation|INFRA_DOCKER|PRODUCER_DOCKER/);
  assert.doesNotMatch(source, /def validate_infra_docker_arguments|"INFRA_DOCKER"|"PRODUCER_DOCKER"/);
});

test("typed infra mappings fix exact release, tmpfs artifacts, images, containers and network policy", () => {
  const value = jsonPython(`
import os,tempfile,types
root=tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root,0o700)
g=m['execute_typed_infra_action'].__globals__; g['TEST_ROOT']=root; g['OWNER_UID']=os.geteuid(); g['OWNER_GID']=os.stat(root).st_gid
commit='1'*40; archive='2'*64; release=m['release_root'](commit,archive); run='20260824T120000Z-a1b2c3d4'
def materialize(logical,data,mode):
 pathname=m['physical'](logical); os.makedirs(os.path.dirname(pathname),mode=0o700,exist_ok=True)
 with open(pathname,'wb') as handle: handle.write(data)
 os.chmod(pathname,mode); return pathname
materialize(f'{release}/scripts/infra-ops.mjs',b'// exact fixture\\n',0o444)
env_bytes=b'KC_BOOTSTRAP_ADMIN_USERNAME=admin\\nPOSTGRES_OPS_SCHEMA=ops\\n'
materialize(m['RENDER_ENV'],env_bytes,0o400)
tools={name:{'imageId':'sha256:'+char*64,'imageReference':f'registry.invalid/{name}@sha256:{char*64}'} for name,char in zip(
 ('mariadbRestore','minioRestore','nodeUtility','postgresRestore','resticRclone'),'34567')}
service_chars={'enterprise-postgres':'a','mariadb':'b','enterprise-minio':'c','enterprise-keycloak':'d'}
targets=[{'containerName':name,'semantic':{'imageId':'sha256:'+char*64,'imageReference':f'registry.invalid/{name}@sha256:{char*64}'}}
 for name,char in service_chars.items()]
authority={'backupToolImages':tools,'candidateCommit':commit,'documentId':'e'*64,'releaseRoot':release,
 'renderEnvironment':{'path':m['RENDER_ENV'],'sha256':m['digest'](env_bytes)},'serviceTargets':targets,'sourceArchiveSha256':archive}
for logical_key in ('pg-stexor','mariadb','minio','keycloak-config'):
 index=m['EVIDENCE_LOGICAL_KEYS'].index(logical_key)+1
 directory=f'/dev/shm/platform-v1-evidence-{run}-transaction/artifact-staging/{index:02d}-{logical_key}'
 payload=f'{logical_key}.fixture'.encode()
 materialize(f'{directory}/{logical_key}.bin',payload,0o400)
 materialize(f'{directory}/{logical_key}.bin.sha256',m['digest'](payload).encode()+b'\\n',0o400)
 materialize(f'{directory}/{logical_key}.bin.sig.json',b'{}\\n',0o400)
calls=[]
def fake_run(command,label,**kwargs):
 operation=command[2]; calls.append({'command':command,'environment':kwargs['environment'],'label':label})
 output=b'backup complete\\n'
 if operation.startswith('restore-test-'):
  artifact=command[command.index('--backupFile')+1]; artifact_sha=m['digest'](open(artifact,'rb').read())
  receipt={'artifactSha256':artifact_sha,'counts':{},'matched':True,'operation':operation,
   'schema':'platform.v1.restore-evidence-receipt/v1','scope':'fixture-exact-restore','semanticComparator':{'matched':True}}
  output=b'fixture\\nV1_EVIDENCE_RECEIPT:'+m['canonical_bytes'](receipt)
 return types.SimpleNamespace(returncode=0,stdout=output,stderr=b'')
original=g['run_result']; g['run_result']=fake_run
actions=[
 ('BACKUP_APPLICATIONS',{'runId':run}),('BACKUP_POSTGRES',{'database':'stexor','runId':run}),
 ('BACKUP_MARIADB',{'runId':run}),('BACKUP_MINIO',{'runId':run}),('BACKUP_KEYCLOAK',{'runId':run}),
 ('BACKUP_SECRET_METADATA',{'runId':run}),('RESTORE_POSTGRES',{'logicalKey':'pg-stexor','runId':run}),
 ('RESTORE_MARIADB',{'runId':run}),('RESTORE_MINIO',{'runId':run}),('RESTORE_KEYCLOAK',{'runId':run}),
]
results=[]
try:
 for action,parameters in actions:
  status,stdout,stderr=m['execute_typed_infra_action'](authority,action,parameters)
  results.append({'action':action,'status':status,'value':json.loads(stdout)})
finally: g['run_result']=original
print(json.dumps({'calls':calls,'results':results,'root':root,'run':run},sort_keys=True))`);
  assert.deepEqual(value.results.map((item) => [item.action, item.status, item.value.status]), [
    "BACKUP_APPLICATIONS", "BACKUP_POSTGRES", "BACKUP_MARIADB", "BACKUP_MINIO", "BACKUP_KEYCLOAK",
    "BACKUP_SECRET_METADATA", "RESTORE_POSTGRES", "RESTORE_MARIADB", "RESTORE_MINIO", "RESTORE_KEYCLOAK",
  ].map((action) => [action, 0, "PASS"]));
  assert.deepEqual(value.calls.map((item) => item.command[2]), [
    "backup-applications", "backup-postgres", "backup-mariadb", "backup-minio", "backup-keycloak",
    "backup-secret-manager-metadata", "restore-test-postgres", "restore-test-mariadb", "restore-test-minio", "restore-test-keycloak",
  ]);
  for (const call of value.calls) {
    assert.equal(call.environment.PLATFORM_V1_EVIDENCE_NETWORK_MODE, "none");
    assert.equal(call.environment.PLATFORM_V1_EVIDENCE_RUN_ID, value.run);
    assert.equal(call.environment.PLATFORM_CLOSED_HOST_PATH_MAPPINGS, "1");
    assert.equal(call.command[call.command.indexOf("--skipEvidence") + 1], "true");
    assert.ok(!call.command.join(" ").includes("enterprise-backup-scheduler"));
  }
  for (const call of value.calls.filter((item) => item.command[2].startsWith("restore-test-"))) {
    const artifact = call.command[call.command.indexOf("--backupFile") + 1];
    assert.ok(artifact.startsWith(`${value.root}/dev/shm/platform-v1-evidence-${value.run}-transaction/artifact-staging/`));
    assert.equal(call.command[call.command.indexOf("--v1EvidenceReceipt") + 1], "true");
  }
  const mappingSource = runPython("import inspect; print(inspect.getsource(m['execute_typed_infra_action'])+inspect.getsource(m['executor_infra_environment']))");
  assert.doesNotMatch(mappingSource, /enterprise-backup-scheduler|INFRA_DOCKER|PRODUCER_DOCKER/);
  assert.match(mappingSource, /PLATFORM_V1_EVIDENCE_NETWORK_MODE.*none/);
  assert.match(mappingSource, /executor_primary_artifact/);
});

test("apply attaches legacy bridges before data and fixed-order one-service refresh", () => {
  const applySource = runPython("import inspect; print(inspect.getsource(m['apply']))");
  const refreshSource = runPython("import inspect; print(inspect.getsource(m['compose_refresh']))");
  const network = applySource.indexOf("ensure_exact_attachment_networks(authority)");
  const attach = applySource.indexOf("apply_network_step(step, journal)");
  const data = applySource.indexOf("apply_data_prerequisites");
  const services = applySource.indexOf("for name in SERVICE_REFRESH_ORDER");
  const remove = applySource.indexOf('if step.get("kind") == "REMOVE"');
  assert.ok(network >= 0 && network < attach && attach < data && data < services && services < remove);
  assert.match(refreshSource, /revalidate_render_before_mutation/);
  assert.match(refreshSource, /"up", "--detach", "--no-deps", "--no-build", "--pull", "never", "--force-recreate"/);
  assert.match(refreshSource, /service,/);
  assert.doesNotMatch(source, /\[docker_binary\(\),\s*"compose"[^\]]*"up"[^\]]*\](?![\s\S]{0,80}service)/);
});

test("marker-before-disable crash cannot create a journal or mutate Docker/data", () => {
  const value = jsonPython(`
import types
g=m['apply'].__globals__; calls=[]
def fake_run(command,label,**kwargs):
 calls.append(['systemctl',command[-2]])
 state=b'enabled\\n' if command[-2]=='is-enabled' else b'active\\n'
 return types.SimpleNamespace(returncode=0,stdout=state,stderr=b'')
g['run_result']=fake_run
g['configure_secret_anchor']=lambda: calls.append(['MUTATION','secret-anchor'])
g['read_authority']=lambda: calls.append(['MUTATION','authority-read-after-gate'])
stopped=False
try: m['apply']()
except m['Stop']: stopped=True
print(json.dumps({'calls':calls,'stopped':stopped}))`);
  assert.equal(value.stopped, true);
  assert.deepEqual(value.calls, [["systemctl", "is-enabled"], ["systemctl", "is-active"]]);
  const applySource = runPython("import inspect; print(inspect.getsource(m['apply']))");
  const evidenceSource = runPython("import inspect; print(inspect.getsource(m['evidence']))");
  const abortSource = runPython("import inspect; print(inspect.getsource(m['abort']))");
  assert.ok(applySource.indexOf("require_maintenance_ready()") < applySource.indexOf("configure_secret_anchor()"));
  assert.ok(applySource.indexOf("require_maintenance_ready()") < applySource.indexOf("read_or_create_journal"));
  assert.ok(evidenceSource.indexOf("require_maintenance_ready()") < evidenceSource.indexOf("read_or_create_journal"));
  assert.match(abortSource, /configure_secret_identity_readonly\(\)[\s\S]*read_or_create_journal[\s\S]*materialize_abort_record/);
  assert.match(runPython("import inspect; print(inspect.getdoc(m['abort']))"), /abort-maintenance[\s\S]*verify/);
});

test("already-correct prerequisites are truthfully skipped and evidence remains a mutation subset", () => {
  assert.match(source, /SKIPPED_VERIFIED/);
  assert.match(source, /status not in \("PENDING", "RUNNING", "APPLIED", "SKIPPED_VERIFIED"\)/);
  assert.match(source, /value not in \("APPLIED", "SKIPPED_VERIFIED"\)/);
  assert.match(source, /\.issubset\(expected_mutations\)/);
  assert.match(source, /status == "APPLIED"\) != \(authority_id in evidence_ids\)/);
  assert.match(source, /runtime_database_login_ready/);
  assert.match(source, /keycloak_staged_ready/);
  assert.match(source, /refresh_local_checkpoint\(authority\)/);
  assert.match(source, /refresh_local_checkpoint\(authority, data, reconciliation\["beganAtUnixSeconds"\]\)/);
  const evidenceSource = runPython("import inspect; print(inspect.getsource(m['evidence']))");
  assert.ok(evidenceSource.indexOf("refresh_local_checkpoint(authority, data") < evidenceSource.indexOf("purge_predecessor_backups(journal)"));
  assert.match(evidenceSource, /stable_canonical_inventory\(journal\)/);
  assert.match(evidenceSource, /journal\["phase"\] == "APPLIED"[\s\S]*invoke_evidence_producer\(authority, "post"\)/);
  assert.match(runPython("import inspect; print(inspect.getsource(m['purge_predecessor_backups']))"), /AFTER_COMMITTING[\s\S]*AFTER_PURGE_/);
});

test("stale post-maintenance evidence leaves checkpoint bytes and rollback phase untouched", () => {
  const value = jsonPython(`
import os,tempfile,time
root=tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root,0o700)
g=m['refresh_local_checkpoint'].__globals__
g['TEST_ROOT']=root; g['OWNER_UID']=os.geteuid(); g['OWNER_GID']=os.stat(root).st_gid
now=int(time.time()); began=now-10
def put(logical,value,mode=0o600):
 p=m['physical'](logical); os.makedirs(os.path.dirname(p),mode=0o700,exist_ok=True)
 data=m['canonical_bytes'](value) if isinstance(value,dict) else value
 if os.path.exists(p): os.chmod(p,0o600)
 open(p,'wb').write(data); os.chmod(p,mode); return data
docs={}
for key,logical in m['CHECKPOINT_EVIDENCE_PATHS'].items():
 docs[key]=put(logical,{'capturedAtUnixSeconds':began-1,'schema':'test'})
export=put(m['SCHEDULER_RECOVERY_EXPORT'],b'fixed-export')
authority={'candidateCommit':'1'*40,'candidateTree':'2'*40,'sourceArchiveSha256':'3'*64}
checkpoint={
 'authoritative':False,'backupCapturedUnixSeconds':now-100,'candidateCommit':authority['candidateCommit'],
 'candidateTree':authority['candidateTree'],'destructiveMutationPlanned':False,'generatedAtUnixSeconds':now-1,
 'logicalBackupEvidenceSha256':m['digest'](docs['logicalBackupEvidenceSha256']),
 'offHostBackupEvidenceSha256':m['digest'](docs['offHostBackupEvidenceSha256']),
 'restoreEvidenceSha256':m['digest'](docs['restoreEvidenceSha256']),'restoreVerified':True,
 'runtimeInventorySha256':m['digest'](docs['runtimeInventorySha256']),'runtimeRecovered':True,
 'schedulerRecoveryImageExportSha256':m['digest'](export),'schedulerRecoveryImageId':'sha256:'+'4'*64,
 'schedulerRunningImageId':'sha256:'+'5'*64,'schema':'platform.v1-local-private-predeploy-checkpoint/v1',
 'secretsBackupEvidenceSha256':m['digest'](docs['secretsBackupEvidenceSha256']),'sourceArchiveSha256':authority['sourceArchiveSha256'],
}
before=put(m['LOCAL_CHECKPOINT'],checkpoint)
runtime=m['canonical_bytes']({'capturedAtUnixSeconds':now,'schema':'runtime'})
put(m['RUNTIME_EVIDENCE'],runtime,0o444)
stopped=False
try: m['refresh_local_checkpoint'](authority,runtime,began)
except m['Stop']: stopped=True
unchanged=open(m['physical'](m['LOCAL_CHECKPOINT']),'rb').read()==before
fresh={}
for key,logical in m['CHECKPOINT_EVIDENCE_PATHS'].items():
 fresh[key]=put(logical,{'capturedAtUnixSeconds':now,'schema':'fresh'},0o444)
runtime=fresh['runtimeInventorySha256']
g['validate_post_checkpoint_evidence']=lambda authority,snapshots,began,observed_now: None
m['refresh_local_checkpoint'](authority,runtime,began)
updated=m['parse_json'](open(m['physical'](m['LOCAL_CHECKPOINT']),'rb').read(),'updated checkpoint')
all_bound=all(updated[key]==m['digest'](fresh[key]) for key in m['CHECKPOINT_EVIDENCE_PATHS'])
print(json.dumps({'allBound':all_bound,'stopped':stopped,'unchanged':unchanged}))`);
  assert.deepEqual(value, { allBound: true, stopped: true, unchanged: true });
});

test("POST backup bundle rejects candidate, artifact, offsite, restore, secret and transaction substitutions", () => {
  const value = jsonPython(`
import base64,copy,hashlib,time
now=int(time.time()); began=now-60; rec='a'*64; tx='b'*64; run_id='20260822T120000Z-1234abcd'
images={name:{'imageId':'sha256:'+char*64,'imageReference':f'registry.invalid/{name}@sha256:{char*64}'} for name,char in zip(
 ('mariadbRestore','minioRestore','nodeUtility','postgresRestore','resticRclone'),'12345')}
authority={'backupToolImages':images,'candidateCommit':'6'*40,'candidateTree':'7'*40,'documentId':'8'*64,
 'recoveryEscrowCertificate':{'path':'/release/config/cert.pem','sha256':'9'*64,'sha256Fingerprint':'c'*64},
 'sourceArchiveSha256':'d'*64}
artifacts=[]
for index,key in enumerate(m['EVIDENCE_LOGICAL_KEYS'],start=1):
 artifact=('confidential.tar.gpg' if key=='confidential' else key+'.tar.gz')
 artifacts.append({'artifact':artifact,'artifactIndex':index,'checksumSidecarPath':'/backup/'+artifact+'.sha256',
  'checksumVerified':True,'freshLocalRestoreVerified':True,'hmacKeyId':'v1-backup-signing-key',
  'hmacSidecarPath':'/backup/'+artifact+'.sig.json','hmacVerified':True,'hostPath':'/backup/'+artifact,
  'logicalKey':key,'sha256':hashlib.sha256(key.encode()).hexdigest(),'sizeBytes':1000+index,'status':'PASS'})
identities=[{key:item[key] for key in ('artifactIndex','logicalKey','sha256','sizeBytes')} for item in artifacts]
common={'artifactSetSha256':m['digest'](m['canonical_bytes'](identities)),'authorityDocumentId':authority['documentId'],
 'authoritySha256':m['digest'](m['canonical_bytes'](authority)),'backupToolImages':images,
 'candidateCommit':authority['candidateCommit'],'candidateTree':authority['candidateTree'],'evidencePhase':'POST',
 'reconciliationSha256':rec,'runId':run_id,'sourceArchiveSha256':authority['sourceArchiveSha256'],'transactionId':tx}
common['backupSetSha256']=m['digest'](m['canonical_bytes']({**common,'artifacts':identities}))
def comparator(operation,artifact_sha):
 scope={'restore-test-postgres':'same-artifact-independent-double-restore','restore-test-mariadb':'same-artifact-independent-double-restore',
  'restore-test-minio':'stable-live-source-before-after-to-isolated-restored-durable-tree',
  'restore-test-keycloak':'same-artifact-independent-double-extract-and-parse'}[operation]
 h=hashlib.sha256(operation.encode()).hexdigest()
 if operation=='restore-test-postgres':
  fingerprint={'combinedSha256':h,'largeObjectBytes':0,'largeObjectRows':0,'largeObjectsSha256':h,'relationCount':1,'rowCount':1,
   'rowDataSha256':h,'schemaBytes':1,'schemaLines':1,'sequenceCount':0,'sequencesSha256':h,'structureSha256':h}
  names=('largeObjectsSha256','rowDataSha256','sequencesSha256','structureSha256'); engine='postgres'; counts={'restoredTables':1}
 elif operation=='restore-test-mariadb':
  fingerprint={'combinedSha256':h,'relationCount':1,'rowCount':1,'rowDataSha256':h,'schemaBytes':1,'schemaCount':1,
   'schemaLines':1,'schemaSetSha256':h,'structureSha256':h}
  names=('rowDataSha256','schemaSetSha256','structureSha256'); engine='mariadb'; counts={'restoredSchemas':1,'restoredTables':1}
 elif operation=='restore-test-keycloak':
  fingerprint={'archiveTreeSha256':h,'canonicalContentSha256':h,'combinedSha256':h,'fileCount':1,'jsonCount':1,
   'rawJsonSetSha256':h,'realmCount':1,'totalJsonBytes':1}
  names=('archiveTreeSha256','canonicalContentSha256','rawJsonSetSha256')
  semantic={'algorithm':'sha256','components':{name:{'firstRestore':h,'matched':True,'secondRestore':h} for name in names},
   'engine':'keycloak','firstRestore':fingerprint,'firstRestoreSha256':h,'matched':True,'scope':scope,
   'secondRestore':fingerprint,'secondRestoreSha256':h,'version':'platform.keycloak-config-restore-semantic-comparator/v1'}
  return {'artifactSha256':artifact_sha,'counts':{'jsonCount':1,'realmCount':1},'matched':True,'operation':operation,
   'schema':'platform.v1.restore-evidence-receipt/v1','scope':scope,'semanticComparator':semantic}
 else:
  exclusions=['.minio.sys/tmp/*','.minio.sys/buckets/.bloomcycle.bin/xl.meta','.minio.sys/buckets/.usage.json/xl.meta']
  tree={'combinedSha256':h,'directoryCount':1,'entryCount':2,'excludedPaths':exclusions,'fileCount':1,'totalFileBytes':1,'treeSha256':h}
  semantic={'algorithm':'sha256','components':{'treeSha256':{'restored':h,'restoredMatchesSource':True,'sourceAfter':h,
   'sourceBefore':h,'sourceStable':True}},'engine':'minio','matched':True,'restored':tree,'restoredMatchesSource':True,
   'restoredSha256':h,'scope':scope,'sourceAfter':tree,'sourceAfterSha256':h,'sourceBefore':tree,'sourceBeforeSha256':h,
   'sourceStable':True,'version':'platform.minio-restore-tree-comparator/v1','volatileExclusions':exclusions}
  return {'artifactSha256':artifact_sha,'counts':{'bootHealthy':True,'restoredDurableEntries':2,'sourceDurableEntries':2},
   'matched':True,'operation':operation,'schema':'platform.v1.restore-evidence-receipt/v1','scope':scope,'semanticComparator':semantic}
 semantic={'algorithm':'sha256','components':{name:{'firstRestore':fingerprint[name],'matched':True,'secondRestore':fingerprint[name]} for name in names},
  'engine':engine,'firstRestore':fingerprint,'firstRestoreSha256':h,'matched':True,'scope':scope,
  'secondRestore':fingerprint,'secondRestoreSha256':h,'version':'platform.database-restore-semantic-comparator/v1'}
 return {'artifactSha256':artifact_sha,'counts':counts,'matched':True,'operation':operation,
  'schema':'platform.v1.restore-evidence-receipt/v1','scope':scope,'semanticComparator':semantic}
def restore_verification(key,artifact_sha):
 h=hashlib.sha256(('restore-'+key).encode()).hexdigest()
 if key in m['EVIDENCE_LOGICAL_KEYS'][:8]: return {'entryCount':1,'restoredTreeSha256':h,'sourceTreeSha256':h}
 if key=='confidential': return {'entryCount':1,'restoredTreeSha256':h,'sourceTreeSha256':h,'treeSha256':h}
 operation={'pg-stexor':'restore-test-postgres','pg-keycloak':'restore-test-postgres','mariadb':'restore-test-mariadb',
  'minio':'restore-test-minio','keycloak-config':'restore-test-keycloak'}[key]
 return {'comparatorReceipt':comparator(operation,artifact_sha)}
proofs=[]; results=[]
for identity,artifact in zip(identities,artifacts):
 snapshot=hashlib.sha256(('snapshot-'+identity['logicalKey']).encode()).hexdigest()
 proofs.append({**identity,'artifact':artifact['artifact'],'offHostLocation':'rclone:platform-onedrive:platform-infrastructure/restic#snapshot='+snapshot,
  'remoteChecksumSidecarByteExact':True,'remoteHmacSidecarByteExact':True,'remotePayloadByteExact':True,
  'snapshotId':snapshot,'snapshotPaths':['/backup/'+artifact['artifact'],'/backup/'+artifact['artifact']+'.sha256','/backup/'+artifact['artifact']+'.sig.json'],
  'snapshotTag':'local-private-v1-'+run_id,'status':'PASS'})
 verification=restore_verification(identity['logicalKey'],identity['sha256'])
 results.append({**identity,'artifact':artifact['artifact'],'isolatedRestore':True,
  'restoreMode':m['RESTORE_MODE_BY_LOGICAL_KEY'][identity['logicalKey']],'status':'PASS','verification':verification,
  'verificationSha256':m['digest'](m['canonical_bytes'](verification))})
summary='e'*64; cipher=b'x'*512
escrow={'certificateSha256':authority['recoveryEscrowCertificate']['sha256'],
 'certificateSha256Fingerprint':authority['recoveryEscrowCertificate']['sha256Fingerprint'],
 'ciphertextBase64':base64.b64encode(cipher).decode(),'ciphertextSha256':hashlib.sha256(cipher).hexdigest(),
 'ciphertextSizeBytes':len(cipher),'offHostLocation':'platform-onedrive:platform-infrastructure/key-escrow/v1-local-private-recovery-'+run_id+'.cms',
 'remotePayloadByteExact':True,'status':'PASS'}
logical={**common,'artifactCount':14,'artifactManifestSha256':m['digest'](b''.join(m['canonical_bytes'](item) for item in artifacts)),
 'artifacts':artifacts,'backupCompletedUnixSeconds':now-20,'capturedAtUnixSeconds':now-20,'checksumVerifiedCount':14,
 'freshArtifactStreamHashCount':14,'generatedAtUnixSeconds':now-5,'hmacVerifiedCount':14,
 'schema':'platform.v1-local-private-logical-backup-evidence/v1','sourceSummarySha256':summary,'status':'PASS',
 'totalArtifactBytes':sum(item['sizeBytes'] for item in artifacts)}
offhost={**common,'artifactCount':14,'completedAtUnixSeconds':now-10,'distinctSnapshotCount':14,'exactPayloadReadbackCount':14,
 'freshExactSnapshotCount':14,'generatedAtUnixSeconds':now-5,'hostingerUsed':False,'noPrune':True,
 'offsiteProofSha256':m['digest'](b''.join(m['canonical_bytes'](item) for item in proofs)),'proofs':proofs,
 'recoveryEscrow':escrow,'repository':'rclone:platform-onedrive:platform-infrastructure/restic','repositoryProvider':'OneDrive',
 'retentionSkipped':True,'schema':'platform.v1-local-private-offhost-backup-evidence/v1','sourceSummarySha256':summary,'status':'PASS'}
restore={**common,'artifactCount':14,'completedAtUnixSeconds':now-15,'expectedRestoreCount':14,'generatedAtUnixSeconds':now-5,
 'localRestoreResultsSha256':m['digest'](b''.join(m['canonical_bytes'](item) for item in results)),'passedRestoreCount':14,
 'results':results,'schema':'platform.v1-local-private-restore-evidence/v1','sourceSummarySha256':summary,'status':'PASS'}
encrypted={key:value for key,value in {**identities[-1],'artifact':artifacts[-1]['artifact'],'checksumVerified':True,'hmacVerified':True,
 'remotePayloadByteExact':True,'snapshotId':proofs[-1]['snapshotId'],'status':'PASS'}.items()}
secret={**common,'backupCompletedUnixSeconds':now-20,'capturedAtUnixSeconds':now-20,'encryptedArtifact':encrypted,
 'generatedAtUnixSeconds':now-5,'plaintextTemporaryStateAbsent':True,'recoveryEscrow':escrow,
 'schema':'platform.v1-local-private-secrets-backup-evidence/v1','secretBindingInventory':{'distinctHostFiles':3,'mountOccurrences':5,
 'problemCount':0,'setSha256':'f'*64,'unmountedReferenceCount':0},'secretRestore':{**results[-1],'treeSha256':results[-1]['verification']['treeSha256']},
 'secretValuesRecorded':False,'sourceSummarySha256':summary,'status':'PASS'}
base={'logicalBackupEvidenceSha256':logical,'offHostBackupEvidenceSha256':offhost,
 'restoreEvidenceSha256':restore,'secretsBackupEvidenceSha256':secret}
m['validate_post_backup_bundle'](authority,base,rec,tx,began,now)
def rejected(mutator):
 candidate=copy.deepcopy(base); mutator(candidate)
 try: m['validate_post_backup_bundle'](authority,candidate,rec,tx,began,now)
 except m['Stop']: return True
 return False
def mutate_restore_verification(d,index,mutator):
 row=d['restoreEvidenceSha256']['results'][index]; mutator(row['verification'])
 row['verificationSha256']=m['digest'](m['canonical_bytes'](row['verification']))
 d['restoreEvidenceSha256']['localRestoreResultsSha256']=m['digest'](b''.join(
  m['canonical_bytes'](item) for item in d['restoreEvidenceSha256']['results']))
mutants={
 'candidate':rejected(lambda d:[item.__setitem__('candidateCommit','0'*40) for item in d.values()]),
 'logicalDigest':rejected(lambda d:d['logicalBackupEvidenceSha256']['artifacts'][0].__setitem__('sha256','0'*64)),
 'offhostPayload':rejected(lambda d:d['offHostBackupEvidenceSha256']['proofs'][0].__setitem__('remotePayloadByteExact',False)),
 'offhostSnapshot':rejected(lambda d:d['offHostBackupEvidenceSha256']['proofs'][13].__setitem__('snapshotId','0'*64)),
 'restoreIsolation':rejected(lambda d:d['restoreEvidenceSha256']['results'][0].__setitem__('isolatedRestore',False)),
 'restoreMode':rejected(lambda d:d['restoreEvidenceSha256']['results'][0].__setitem__('restoreMode','WRONG')),
 'restoreTrees':rejected(lambda d:mutate_restore_verification(d,0,lambda v:v.__setitem__('sourceTreeSha256','0'*64))),
 'restoreComparator':rejected(lambda d:mutate_restore_verification(d,8,lambda v:v['comparatorReceipt'].__setitem__('matched',False))),
 'secretBinding':rejected(lambda d:d['secretsBackupEvidenceSha256']['encryptedArtifact'].__setitem__('sha256','0'*64)),
 'secretTree':rejected(lambda d:d['secretsBackupEvidenceSha256']['secretRestore'].__setitem__('treeSha256','0'*64)),
 'escrowCiphertext':rejected(lambda d:d['secretsBackupEvidenceSha256']['recoveryEscrow'].__setitem__('ciphertextSha256','0'*64)),
 'transaction':rejected(lambda d:[item.__setitem__('transactionId','0'*64) for item in d.values()]),
 'extraField':rejected(lambda d:d['restoreEvidenceSha256'].__setitem__('untrusted',True)),
}
print(json.dumps({'baseline':True,'mutants':mutants},sort_keys=True))`);
  assert.equal(value.baseline, true);
  assert.deepEqual(value.mutants, {
    candidate: true,
    escrowCiphertext: true,
    extraField: true,
    logicalDigest: true,
    offhostPayload: true,
    offhostSnapshot: true,
    restoreIsolation: true,
    restoreComparator: true,
    restoreMode: true,
    restoreTrees: true,
    secretBinding: true,
    secretTree: true,
    transaction: true,
  });
});

test("abort restores checkpoint plus five evidence preimages after every partial replace boundary", () => {
  const value = jsonPython(`
import os,tempfile,stat
root=tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root,0o700)
g=m['materialize_evidence_preimages'].__globals__; g['TEST_ROOT']=root; g['OWNER_UID']=os.geteuid(); g['OWNER_GID']=os.stat(root).st_gid
def write(logical,data,mode):
 p=m['physical'](logical); os.makedirs(os.path.dirname(p),mode=0o700,exist_ok=True)
 if os.path.exists(p): os.chmod(p,0o600)
 open(p,'wb').write(data); os.chmod(p,mode)
sources=m['evidence_preimage_sources'](); originals={}
for index,logical in enumerate(sources):
 data=('preimage-%02d'%index).encode(); mode=0o400 if index%2 else 0o600
 write(logical,data,mode); originals[logical]=(data,mode)
tx='a'*64; entries=m['materialize_evidence_preimages'](tx); journal={'evidencePreimages':entries,'transactionId':tx}
passes=[]
for cut in range(1,len(sources)+1):
 for index,logical in enumerate(sources[:cut]): write(logical,('replacement-%02d'%index).encode(),0o444)
 m['restore_evidence_preimages'](journal)
 passes.append(all(open(m['physical'](logical),'rb').read()==originals[logical][0] and stat.S_IMODE(os.stat(m['physical'](logical)).st_mode)==originals[logical][1] for logical in sources))
print(json.dumps({'count':len(entries),'passes':passes,'checkpointLast':sources[-1]==m['LOCAL_CHECKPOINT']}))`);
  assert.equal(value.count, 6);
  assert.equal(value.checkpointLast, true);
  assert.deepEqual(value.passes, [true, true, true, true, true, true]);
});

test("residual mutation abort is immutable, controller-bound, finalized, and retry-unblocked", () => {
  const value = jsonPython(`
import os,tempfile,time
root=tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root,0o700)
g=m['materialize_abort_record'].__globals__; g['TEST_ROOT']=root; g['OWNER_UID']=os.geteuid(); g['OWNER_GID']=os.stat(root).st_gid
def put(logical,data,mode):
 p=m['physical'](logical); os.makedirs(os.path.dirname(p),mode=0o700,exist_ok=True); open(p,'wb').write(data); os.chmod(p,mode)
doc='d'*64; authority={'authorizedDataMutations':[{'id':'mutation-one'}],'documentId':doc}; authority_bytes=m['canonical_bytes'](authority)
evidence_doc={'authorityId':'mutation-one','capturedAtUnixSeconds':int(time.time()),'detailsSha256':'1'*64,'schema':m['MUTATION_EVIDENCE_SCHEMA'],'status':'PASS'}
evidence_bytes=m['canonical_bytes'](evidence_doc); evidence_sha=m['digest'](evidence_bytes)
evidence_path=f"{m['MUTATION_EVIDENCE_DIR']}/{doc}-mutation-one-{evidence_sha}.json"; put(evidence_path,evidence_bytes,0o444)
entry={'authorityId':'mutation-one','evidencePath':evidence_path,'evidenceSha256':evidence_sha}; tx='a'*64; now=int(time.time())
journal={'authorityDocumentId':doc,'authoritySha256':m['digest'](authority_bytes),'beganAtUnixSeconds':now-1,'createdAtUnixSeconds':now-1,
 'dataMutationEvidence':[entry],'dataMutationStatus':{'mutation-one':'APPLIED'},'deploymentConfigPreimage':{},'evidencePreimages':[],
 'phase':'ABORTED','reconciliationSha256':'2'*64,'schema':m['JOURNAL_SCHEMA'],'steps':[],'transactionId':tx,'updatedAtUnixSeconds':now}
put(m['JOURNAL'],m['canonical_bytes'](journal),0o600)
record,record_data,archive=m['materialize_abort_record'](authority,authority_bytes,journal)
binding={**record,'recordPath':archive,'recordSha256':m['digest'](record_data)}
receipt={'abortedAuthorizedReconciliation':binding,'schema':'platform.v1-local-private-control-receipt/v1','status':'ACTIVE'}
receipt_bytes=m['canonical_bytes'](receipt); put(m['ACTIVE_RECEIPT'],receipt_bytes,0o444); g['PREVERIFIED_CONTROLLER_RECEIPT']=receipt_bytes
result=m['finalize_consumed_abort'](authority,authority_bytes)
print(json.dumps({'archiveExists':os.path.exists(m['physical'](result['journalArchivePath'])),'currentRecord':os.path.exists(m['physical'](m['ABORT_RECORD'])),'journal':os.path.exists(m['physical'](m['JOURNAL'])),'recordStatus':record['status'],'resultStatus':result['status']}))`);
  assert.deepEqual(value, {
    archiveExists: true,
    currentRecord: false,
    journal: false,
    recordStatus: "ABORTED_WITH_RESIDUAL_DATA_MUTATIONS",
    resultStatus: "ABORT_FINALIZED",
  });
});

test("sealed EVIDENCED journal is archived and removed before the next prepare", () => {
  const value = jsonPython(`
import os,tempfile,time
root=tempfile.mkdtemp(dir=os.path.realpath(tempfile.gettempdir())); os.chmod(root,0o700)
g=m['finalize_evidenced_journal'].__globals__; g['TEST_ROOT']=root; g['OWNER_UID']=os.geteuid(); g['OWNER_GID']=os.stat(root).st_gid
def put(logical,data,mode):
 p=m['physical'](logical); os.makedirs(os.path.dirname(p),mode=0o700,exist_ok=True); open(p,'wb').write(data); os.chmod(p,mode)
doc='d'*64; authority={'documentId':doc}; authority_bytes=m['canonical_bytes'](authority); tx='b'*64; now=int(time.time())
private=[]
for index in range(2):
 logical=f"{m['ROLLBACK_SPEC_DIR']}/{tx}/evidence-preimages/{index:02d}.bin"; data=f'private-{index}'.encode(); put(logical,data,0o600)
 private.append({'logicalPath':'/unused/'+str(index),'mode':0o400,'preimagePath':logical,'sha256':m['digest'](data),'sizeBytes':len(data)})
journal={'authorityDocumentId':doc,'authoritySha256':m['digest'](authority_bytes),'beganAtUnixSeconds':now-2,'createdAtUnixSeconds':now-2,
 'dataMutationEvidence':[],'dataMutationStatus':{},'deploymentConfigPreimage':private[0],'evidencePreimages':[private[1]],'phase':'EVIDENCED',
 'reconciliationSha256':'2'*64,'schema':m['JOURNAL_SCHEMA'],'steps':[],'transactionId':tx,'updatedAtUnixSeconds':now}
put(m['JOURNAL'],m['canonical_bytes'](journal),0o600); runtime=m['canonical_bytes']({'status':'PASS'}); checkpoint=m['canonical_bytes']({'status':'PASS'})
put(m['RUNTIME_EVIDENCE'],runtime,0o444); put(m['LOCAL_CHECKPOINT'],checkpoint,0o400)
external={'dataMutations':[],'releaseAuthorityDocumentId':doc,'releaseAuthoritySha256':m['digest'](authority_bytes),'runtimeEvidenceSha256':m['digest'](runtime),'status':'SEALED'}
receipt={'checkpointSha256':m['digest'](checkpoint),'externalAuthorizedReconciliation':external,'schema':'platform.v1-local-private-control-receipt/v1','status':'ACTIVE'}
receipt_bytes=m['canonical_bytes'](receipt); put(m['ACTIVE_RECEIPT'],receipt_bytes,0o444); g['PREVERIFIED_CONTROLLER_RECEIPT']=receipt_bytes
result=m['finalize_evidenced_journal'](authority,authority_bytes)
print(json.dumps({'archive':os.path.exists(m['physical'](result['journalArchivePath'])),'current':os.path.exists(m['physical'](m['JOURNAL'])),'private':any(os.path.exists(m['physical'](item['preimagePath'])) for item in private),'status':result['status']}))`);
  assert.deepEqual(value, { archive: true, current: false, private: false, status: "EVIDENCED_FINALIZED" });
  const prepareSource = runPython("import inspect; print(inspect.getsource(m['prepare']))");
  assert.match(prepareSource, /phase.*EVIDENCED[\s\S]*finalize_evidenced_journal/);
});

test("Compose-discovered predecessor loss is recoverable from a private exact inspect spec", () => {
  const value = jsonPython(`
image='sha256:'+'1'*64
raw={
 'Image':image,
 'Config':{'Image':'registry.invalid/old@'+image,'Labels':{}},
 'HostConfig':{'NetworkMode':'net-a'},
 'NetworkSettings':{'Networks':{
   'net-a':{'Aliases':['old'],'IPAMConfig':{'IPv4Address':'172.20.0.2'}},
   'net-b':{'Aliases':['old','legacy'],'IPAMConfig':None},
 }},
}
before={'imageId':image,'imageReference':'registry.invalid/old@'+image,'networkMembership':[
 {'aliases':['old'],'networkName':'net-a'}, {'aliases':['legacy','old'],'networkName':'net-b'},
]}
payload,primary,additional=m['rollback_create_payload'](raw,before)
expected={'name':'old','containerId':'a'*64,'configHash':'b'*64,'exitCode':0,'health':'healthy','imageId':image,'imageReference':before['imageReference'],'networkMembership':before['networkMembership'],'project':'p','runtimeConfigSha256':'c'*64,'semanticSha256':'d'*64,'service':'s','state':'running'}
actual=dict(expected); actual['containerId']='e'*64
print(json.dumps({'additional':additional,'matches':m['recreated_identity_matches'](actual,expected),'payload':payload,'primary':primary}))`);
  assert.equal(value.primary, "net-a");
  assert.equal(value.payload.HostConfig.NetworkMode, "net-a");
  assert.deepEqual(value.payload.NetworkingConfig.EndpointsConfig["net-a"].Aliases, ["old"]);
  assert.deepEqual(value.additional, [{ aliases: ["legacy", "old"], networkName: "net-b", ipv4Address: "", ipv6Address: "" }]);
  assert.equal(value.matches, true, "recreated identity may differ only in containerId");
  assert.match(source, /ROLLBACK_SPEC_SCHEMA/);
  assert.match(source, /preserve_private_json/);
  assert.match(source, /if backup is None:[\s\S]{0,180}recreate_predecessor/);
  assert.match(source, /Docker Engine rollback request was rejected.*response was suppressed/);
  assert.doesNotMatch(source, /identity_matches_predecessor\([^\n]+before\).*containerId.*must/);
});
