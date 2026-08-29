import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const controller = path.join(repositoryRoot, "scripts/v1-local-private-control.py");
const python = process.env.CODEX_PYTHON ?? "python3";

function runPython(source) {
  const result = spawnSync(python, ["-c", source], { cwd: repositoryRoot, encoding: "utf8", maxBuffer: 4 * 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("controller runtime identity projection requires the exact Compose extension", () => {
  const output = runPython(String.raw`
import copy, importlib.util, json
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
commit='1'*40; tree='2'*40; lock=b'{"state":"verified"}\\n'; release='/srv/platform-infrastructure/releases/test'
source={'name':'platform_infra_vps','services':{service:{'image':'registry.invalid/'+service+'@sha256:'+'3'*64} for service in m.MANAGED_CONTAINER_BY_SERVICE}}
source_bytes=m.canonical_bytes(source); source_sha=m.digest(source_bytes); lock_sha=m.digest(lock)
candidate=m.digest(m.canonical({'candidateCommit':commit,'candidateTree':tree,'sourceRenderSha256':source_sha,'workloadLockSha256':lock_sha}).encode())
identity={'candidateId':candidate,'commit':commit,'deploymentId':'v1-local-private:'+candidate,'sourceRenderSha256':source_sha,'tree':tree,'workloadLockSha256':lock_sha}
labels={
 'com.platform.runtime.candidate-id':candidate,
 'com.platform.runtime.commit':commit,
 'com.platform.runtime.deployment-id':'v1-local-private:'+candidate,
 'com.platform.runtime.source-render-sha256':source_sha,
 'com.platform.runtime.tree':tree,
 'com.platform.runtime.workload-lock-sha256':lock_sha,
}
final=copy.deepcopy(source); final['x-platform-runtime-labels']=dict(labels)
for service in final['services'].values(): service['labels']=dict(labels)
environment={
 'PLATFORM_RUNTIME_CANDIDATE_ID':candidate,
 'PLATFORM_RUNTIME_COMMIT':commit,
 'PLATFORM_RUNTIME_DEPLOYMENT_ID':'v1-local-private:'+candidate,
 'PLATFORM_RUNTIME_SOURCE_RENDER_SHA256':source_sha,
 'PLATFORM_RUNTIME_TREE':tree,
 'PLATFORM_RUNTIME_WORKLOAD_LOCK_SHA256':lock_sha,
}
environment_lines=[name+'='+value for name,value in environment.items()]
m.secure_file=lambda *_args,**_kwargs: lock
accepted=m.validate_runtime_identity(identity,final,environment_lines,commit,tree,release)==identity
rejected={}
missing=copy.deepcopy(final); del missing['x-platform-runtime-labels']
wrong=copy.deepcopy(final); wrong['x-platform-runtime-labels']['com.platform.runtime.commit']='4'*40
extra=copy.deepcopy(final); extra['x-platform-runtime-labels']['unexpected']='value'
drift=copy.deepcopy(final); drift['services']['postgres']['image']='registry.invalid/postgres@sha256:'+'5'*64
for name,candidate_render in (('missing',missing),('wrong',wrong),('extra',extra),('drift',drift)):
 try: m.validate_runtime_identity(identity,candidate_render,environment_lines,commit,tree,release); rejected[name]=False
 except m.Stop: rejected[name]=True
print(json.dumps({'accepted':accepted,'rejected':rejected}))
`);
  assert.deepEqual(output, {
    accepted: true,
    rejected: { drift: true, extra: true, missing: true, wrong: true },
  });
});

test("controller predecessor identity accepts only the closed canonical 12-field form", () => {
  const output = runPython(String.raw`
import copy, importlib.util, json
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
h='1'*64
identity={
 'configHash':h,'containerId':'2'*64,'exitCode':0,'health':'healthy',
 'imageId':'sha256:'+'3'*64,'imageReference':'registry.invalid/app@sha256:'+'3'*64,
 'name':'enterprise-app','networkMembership':[
   {'aliases':['app','enterprise-app'],'networkName':'a_net'},
   {'aliases':['app'],'networkName':'b_net'},
 ],
 'runtimeConfigSha256':'4'*64,'semanticSha256':'5'*64,'service':'app','state':'running',
}
accepted=m.validate_recorded_predecessor_identity(identity,'fixture')==identity
variants={
 'extra':dict(identity,project='platform_infra_vps'),
 'missing':{key:value for key,value in identity.items() if key!='semanticSha256'},
 'badSha':dict(identity,containerId='not-a-sha'),
 'aliasOrder':dict(identity,networkMembership=[{'aliases':['enterprise-app','app'],'networkName':'a_net'}]),
 'networkOrder':dict(identity,networkMembership=list(reversed(identity['networkMembership']))),
 'duplicateNetwork':dict(identity,networkMembership=[identity['networkMembership'][0],identity['networkMembership'][0]]),
}
rejected={}
for name,value in variants.items():
 try: m.validate_recorded_predecessor_identity(value,'fixture'); rejected[name]=False
 except m.Stop: rejected[name]=True
print(json.dumps({'accepted':accepted,'fieldCount':len(identity),'rejected':rejected},sort_keys=True))
`);
  assert.deepEqual(output, {
    accepted: true,
    fieldCount: 12,
    rejected: { aliasOrder: true, badSha: true, duplicateNetwork: true, extra: true, missing: true, networkOrder: true },
  });
});

test("controller revalidation matches PRE composite durations and inline config semantics", () => {
  const output = runPython(String.raw`
import importlib.util, json
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
positives={item:m.duration_nanoseconds(item,'fixture') for item in ('20s','1m0s','1h2m3s4ms5us6ns')}
duration_rejected={}
for item in ('','1s1m','1m0m','1m0sX','1.5s'):
 try: m.duration_nanoseconds(item,'fixture'); duration_rejected[item]=False
 except m.Stop: duration_rejected[item]=True
render={'configs':{'routes':{'content':'http:\\n','name':'platform_routes'}},'secrets':{}}
service={'configs':[{'source':'routes','target':'/etc/routes.yml'}]}
inline_mounts=m.render_mounts(render,service,'platform','fixture')
content_drift={'configs':{'routes':{'content':'http:\\n# drift\\n','name':'platform_routes'}},'secrets':{}}
content_bound=m.digest(m.canonical_bytes(render)) != m.digest(m.canonical_bytes(content_drift))
inline_rejected={}
for name,candidate in (
 ('read-only',dict(service,read_only=True)),
 ('reference-extra',{'configs':[{'source':'routes','target':'/etc/routes.yml','mode':292}]}),
):
 try: m.render_mounts(render,candidate,'platform','fixture'); inline_rejected[name]=False
 except m.Stop: inline_rejected[name]=True
wrong={'configs':{'routes':{'content':'http:\\n','name':'platform_routes','file':'/tmp/routes'}},'secrets':{}}
try: m.render_mounts(wrong,service,'platform','fixture'); inline_rejected['definition-extra']=False
except m.Stop: inline_rejected['definition-extra']=True
print(json.dumps({'positives':positives,'durationRejected':duration_rejected,'inlineMounts':inline_mounts,'inlineRejected':inline_rejected,'contentBound':content_bound},sort_keys=True))
`);
  assert.deepEqual(output, {
    contentBound: true,
    durationRejected: { "": true, "1.5s": true, "1m0m": true, "1m0sX": true, "1s1m": true },
    inlineMounts: [],
    inlineRejected: { "definition-extra": true, "read-only": true, "reference-extra": true },
    positives: {
      "1h2m3s4ms5us6ns": 3_723_004_005_006,
      "1m0s": 60_000_000_000,
      "20s": 20_000_000_000,
    },
  });
});

test("pure reconciliation model removes scheduler, retains legacy, and derives mutation truth", () => {
  const output = runPython(String.raw`
import importlib.util, json
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
def identity(name, service=None):
    h=(name.encode().hex()+"0"*64)[:64]
    return {"configHash":h,"containerId":h,"exitCode":0,"health":"none" if name in ("phppgadmin","enterprise-broker-auth-bootstrap") else "healthy","imageAvailability":"LOCAL_IMAGE_STORE","imageId":"sha256:"+h,"imageReference":"registry/"+name+"@sha256:"+h,"name":name,"networkMembership":[{"aliases":[name],"networkName":"enterprise_net"}],"project":"opstudents" if name=="node-opstudents" else "platform_infra_vps","runtimeConfigSha256":h,"semanticSha256":h,"service":service or name.removeprefix("enterprise-"),"state":"exited" if name in ("phppgadmin","enterprise-broker-auth-bootstrap") else "running"}
current=[identity(name, "broker-auth-bootstrap" if name==m.BROKER_AUTH_BOOTSTRAP else "platform-alert-dispatcher" if name==m.CANONICAL_ALERT_DISPATCHER else None) for name in m.CANONICAL_CONTAINERS]
previous=[dict(item) for item in current if item["name"] not in (m.BROKER_AUTH_BOOTSTRAP,m.CANONICAL_ALERT_DISPATCHER)]
previous.append(identity("enterprise-backup-scheduler","backup-scheduler"))
transitions=m.reconciliation_service_transitions(previous,{"containers":current})
runtime={"candidateId":"e"*64,"commit":"f"*40,"deploymentId":"v1-local-private:"+"e"*64,"sourceRenderSha256":"1"*64,"tree":"2"*40,"workloadLockSha256":"3"*64}
legacy=[dict(item) for item in m.LEGACY_UNMANAGED_CONTAINERS]
m.EXACT_AUTHORITY={"authorizedDataMutations":[],"documentId":"a"*64,"legacyNetworkAttachments":[],"legacyUnmanagedContainers":legacy,"runtimeIdentity":runtime}
m.EXACT_AUTHORITY_SHA256="b"*64
external=m.external_reconciliation_document({"beganAtUnixSeconds":1800000000,"legacyUnmanagedContainers":legacy,"previousReceiptDocumentId":"c"*64,"releaseAuthorityDocumentId":"a"*64,"releaseAuthoritySha256":"b"*64,"runtimeIdentity":runtime},"d"*64,transitions,[],[])
print(json.dumps({"count":len(transitions),"legacyChanged":[t for t in transitions if t["current"] and t["current"]["name"] in m.PRESERVED_LEGACY_CONTAINERS and t["status"]!="RETAINED"],"removed":[t["previous"]["name"] for t in transitions if t["status"]=="REMOVED"],"containerRecreate":external["containerRecreate"],"dockerMutation":external["externalDockerMutation"],"dataMutation":external["dataMutation"]}))
`);
  assert.equal(output.count, 37);
  assert.deepEqual(output.removed, ["enterprise-backup-scheduler"]);
  assert.deepEqual(output.legacyChanged, []);
  assert.equal(output.containerRecreate, true);
  assert.equal(output.dockerMutation, true);
  assert.equal(output.dataMutation, false);
});

test("legacy network model permits only authority-listed additive attachments and detects recreation", () => {
  const output = runPython(String.raw`
import importlib.util, json
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
def rec(name):
    h=(name.encode().hex()+"0"*64)[:64]
    return {"configHash":h,"containerId":h,"imageId":"sha256:"+h,"imageReference":"registry/"+name+"@sha256:"+h,"name":name,"networkMembership":[{"aliases":[name],"networkName":"enterprise_net"}],"runtimeConfigSha256":h,"service":name.removeprefix("enterprise-")}
previous=[rec(name) for name in sorted(m.PRESERVED_LEGACY_CONTAINERS)]
current=[]
for name in m.CANONICAL_CONTAINERS:
    item=rec(name)
    item.update({"exitCode":0,"health":"none" if name in ("phppgadmin",m.BROKER_AUTH_BOOTSTRAP) else "healthy","imageAvailability":"LOCAL_IMAGE_STORE","project":"opstudents" if name=="node-opstudents" else "platform_infra_vps","semanticSha256":"f"*64,"state":"exited" if name in ("phppgadmin",m.BROKER_AUTH_BOOTSTRAP) else "running"})
    current.append(item)
attachment={"aliases":["backend"],"containerName":"enterprise-backend","networkName":"platform_infra_vps_routing"}
m.EXACT_AUTHORITY={"legacyNetworkAttachments":[attachment]}
next(item for item in current if item["name"]=="enterprise-backend")["networkMembership"].append({"aliases":["backend"],"networkName":"platform_infra_vps_routing"})
next(item for item in current if item["name"]=="enterprise-backend")["networkMembership"].sort(key=lambda x:x["networkName"])
additions,memberships=m.validate_legacy_network_target(previous,{"containers":current})
blocked=False
next(item for item in current if item["name"]=="enterprise-backend")["containerId"]="e"*64
try: m.validate_legacy_network_target(previous,{"containers":current})
except m.Stop: blocked=True
print(json.dumps({"additions":additions,"membershipCount":len(memberships),"recreationBlocked":blocked}))
`);
  assert.deepEqual(output.additions, [{ aliases: ["backend"], containerName: "enterprise-backend", networkName: "platform_infra_vps_routing" }]);
  assert.equal(output.membershipCount, 19);
  assert.equal(output.recreationBlocked, true);
});

test("no-op repeated reconciliation has no synthetic mutation requirement", () => {
  const output = runPython(String.raw`
import importlib.util, json
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
def rec(name):
    h=(name.encode().hex()+"0"*64)[:64]
    return {"configHash":h,"containerId":h,"imageId":"sha256:"+h,"imageReference":"registry/"+name+"@sha256:"+h,"name":name,"runtimeConfigSha256":h,"service":name.removeprefix("enterprise-")}
records=[rec(name) for name in m.CANONICAL_CONTAINERS]
observation={"containers":[dict(item,exitCode=0,health="healthy",imageAvailability="LOCAL_IMAGE_STORE",networkMembership=[],project="platform_infra_vps",semanticSha256="f"*64,state="running") for item in records]}
# A new reconciliation marker is always captured with the installed full
# semantic projection, even when its predecessor ACTIVE state used the
# registered legacy projection.
transitions=m.reconciliation_service_transitions(records,observation)
runtime={"candidateId":"e"*64,"commit":"f"*40,"deploymentId":"v1-local-private:"+"e"*64,"sourceRenderSha256":"1"*64,"tree":"2"*40,"workloadLockSha256":"3"*64}
legacy=[dict(item) for item in m.LEGACY_UNMANAGED_CONTAINERS]
m.EXACT_AUTHORITY={"authorizedDataMutations":[],"documentId":"a"*64,"legacyNetworkAttachments":[],"legacyUnmanagedContainers":legacy,"runtimeIdentity":runtime}; m.EXACT_AUTHORITY_SHA256="b"*64
external=m.external_reconciliation_document({"beganAtUnixSeconds":1800000000,"legacyUnmanagedContainers":legacy,"previousReceiptDocumentId":"c"*64,"releaseAuthorityDocumentId":"a"*64,"releaseAuthoritySha256":"b"*64,"runtimeIdentity":runtime},"d"*64,transitions,[],[])
control=next(t for t in transitions if t["current"]["name"]=="enterprise-control-center")
print(json.dumps({"statuses":sorted(set(t["status"] for t in transitions)),"digestPreserved":control["previous"]["runtimeConfigSha256"] != control["current"]["runtimeConfigSha256"],"containerRecreate":external["containerRecreate"],"dockerMutation":external["externalDockerMutation"],"dataMutation":external["dataMutation"]}))
`);
  assert.deepEqual(output.statuses, ["RETAINED"]);
  assert.equal(output.digestPreserved, false);
  assert.equal(output.containerRecreate, false);
  assert.equal(output.dockerMutation, false);
  assert.equal(output.dataMutation, false);
});

test("abort is sudo-exposed, idempotent, and has explicit crash boundaries before marker removal", () => {
  const source = fs.readFileSync(controller, "utf8");
  const sudoers = fs.readFileSync(path.join(repositoryRoot, "sudoers/platform-v1-local-private-control"), "utf8");
  assert.match(source, /def abort_maintenance\(\)/);
  for (const boundary of ["AFTER_STATE_REBASELINE", "AFTER_RECEIPT_REBASELINE", "AFTER_SUPERVISOR_ACTIVATION", "BEFORE_MARKER_REMOVAL"]) assert.match(source, new RegExp(boundary));
  assert.match(source, /if not os\.path\.lexists\(physical\(RECONCILIATION_FILE\)\):\s*return verify_active\(\)/s);
  assert.match(source, /ensure_supervisor_active\(\).*remove_exact_document\(RECONCILIATION_FILE/s);
  assert.match(sudoers, /platform-v1-local-private-control abort-maintenance/);
});

test("canonical abort fails before mutation on install drift and rebinds ACTIVE state to the validated current install", () => {
  const output = runPython(String.raw`
import importlib.util, json
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
current="a"*64; previous="b"*64; foreign="c"*64
identities=[{"name":"canonical"}]
observation={"containers":[],"schedulerRecovery":{}}
marker={"installReceiptSha256":current,"predecessorRuntimeIdentities":identities}
previous_state={"checkpointSha256":"d"*64,"installReceiptSha256":previous,"observation":observation}
events=[]; captured=[]
m.os.path.lexists=lambda *_: True
m.read_reconciliation=lambda: marker
m.consume_current_abort_record=lambda *_: events.append("consume") or {}
m.validate_reconciliation_rollback=lambda *_: (previous_state,{})
m.observation_names=lambda *_: m.CANONICAL_EXPECTED_NAMES
m.stable_runtime_identities=lambda *_: identities
m.supervisor_is_disabled_and_inactive=lambda: True
m.predecessor_controller_identity_projection=lambda *_: "FULL_34"
m.predecessor_runtime_provenance_document=lambda *_: {"profile":"CANONICAL_RECONCILED_V1"}
m.stable_observation=lambda *_args,**_kwargs: observation
def state_document(status, observed, install_sha, checkpoint_sha, created, external=None, aborted=None, provenance=None):
    captured.append(install_sha)
    return {"status":status,"installReceiptSha256":install_sha}
m.state_document=state_document
m.atomic_write=lambda *_args,**_kwargs: events.append("write")
m.receipt_from_state=lambda *_: {}
m.ensure_supervisor_active=lambda: events.append("supervisor")
m.remove_exact_document=lambda *_: events.append("remove")
m.verify_active=lambda: {"status":"ACTIVE"}
m.validate_release_and_install=lambda: foreign
blocked=False
try: m.abort_maintenance()
except m.Stop: blocked=True
before=list(events)
m.validate_release_and_install=lambda: current
result=m.abort_maintenance()
print(json.dumps({"blocked":blocked,"before":before,"captured":captured,"result":result,"events":events}))
`);
  assert.deepEqual(output, {
    blocked: true,
    before: [],
    captured: ["a".repeat(64)],
    result: { status: "ACTIVE" },
    events: ["consume", "write", "write", "supervisor", "remove"],
  });
});

test("canonical abort state validates the one registered LEGACY_19 to FULL_34 runtime projection bridge", () => {
  const output = runPython(String.raw`
import copy, importlib.util, json
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
old_commit='1'*40; old_tree='2'*40; old_archive='3'*64
new_commit='4'*40; new_tree='5'*40; new_archive='6'*64
old_controller='f60c20fabeaf3f68b2478ebe31018d52d2d9a967a3598c2ac8256bc01dd33f7d'
new_controller='7'*64
current_controller={'installedPath':m.CONTROLLER_PATH,'sha256':new_controller,'sudoersPath':m.SUDOERS_PATH,'sudoersSha256':'8'*64,'unitPath':m.UNIT_PATH,'unitSha256':'9'*64}
m.controller_identity=lambda:dict(current_controller)
m.validate_aborted_reconciliation_binding=lambda value:value
m.CANDIDATE_COMMIT=new_commit; m.CANDIDATE_TREE=new_tree; m.SOURCE_ARCHIVE_SHA256=new_archive
m.RELEASE_ROOT=f'/srv/platform-infrastructure/releases/{new_commit}-{new_archive}'
runtime={'candidateId':'a'*64,'commit':old_commit,'deploymentId':'v1-local-private:'+'a'*64,'sourceRenderSha256':'b'*64,'tree':old_tree,'workloadLockSha256':'c'*64}
authority={
 'artifacts':{'composeWrapper':{},'controller':{'path':m.CONTROLLER_PATH,'sha256':old_controller},'installer':{},'reconciler':{},'sudoers':{},'unit':{}},
 'authorizedDataMutations':[],'candidateCommit':old_commit,'candidateTree':old_tree,
 'documentId':'d'*64,'legacyNetworkAttachments':[],
 'legacyUnmanagedContainers':[dict(item) for item in m.LEGACY_UNMANAGED_CONTAINERS],
 'releaseRoot':f'/srv/platform-infrastructure/releases/{old_commit}-{old_archive}',
 'runtimeIdentity':runtime,'sourceArchiveSha256':old_archive,
}
m.EXACT_AUTHORITY=authority; m.EXACT_AUTHORITY_SHA256='e'*64
semantic={
 'capAdd':[],'capDrop':[],'command':[],'entrypoint':[],'environment':[],
 'healthcheck':None,'imageId':'sha256:'+'f'*64,'imageReference':'registry.invalid/app@sha256:'+'f'*64,
 'init':False,'mounts':[],'networkMode':'default','networkEndpoints':[],'networks':[],
 'pidsLimit':0,'ports':[],'privileged':False,'readOnlyRootfs':False,'restartPolicy':'unless-stopped',
 'securityOpt':[],'user':'','workingDirectory':'/srv/full-34',
}
legacy_digest=m.projected_runtime_configuration_digest(semantic,m.CONTROLLER_IDENTITY_PROJECTION_LEGACY_19)
full_digest=m.projected_runtime_configuration_digest(semantic,m.CONTROLLER_IDENTITY_PROJECTION_FULL_34)
def service(name):
 return 'broker-auth-bootstrap' if name==m.BROKER_AUTH_BOOTSTRAP else 'platform-alert-dispatcher' if name==m.CANONICAL_ALERT_DISPATCHER else name.removeprefix('enterprise-')
containers=[]; transitions=[]
for index,name in enumerate(m.CANONICAL_CONTAINERS):
 h=f'{index+1:064x}'
 common={'configHash':h,'containerId':f'{index+101:064x}','imageId':'sha256:'+f'{index+201:064x}','imageReference':'registry.invalid/'+name+'@sha256:'+f'{index+201:064x}','name':name}
 record={**common,'runtimeConfigSha256':full_digest,'service':service(name)}
 containers.append(record)
 historical={**common,'runtimeConfigSha256':legacy_digest}
 transitions.append({'current':dict(historical),'previous':dict(historical),'service':service(name),'status':'RETAINED'})
external={
 'authority':'ROOT_OPERATOR_EXPLICIT_V1_RECONCILIATION','beganAtUnixSeconds':1800000000,
 'containerRecreate':False,'controllerDockerMutation':False,'dataMutation':False,'dataMutations':[],
 'dataMutationsSha256':m.digest(m.canonical([]).encode()),'externalDockerMutation':False,
 'legacyNetworkAttachments':[],'legacyNetworkAttachmentsSha256':m.digest(m.canonical([]).encode()),
 'legacyUnmanagedContainers':[dict(item) for item in m.LEGACY_UNMANAGED_CONTAINERS],
 'previousReceiptDocumentId':'1'*64,'releaseAuthorityDocumentId':authority['documentId'],
 'releaseAuthoritySha256':m.EXACT_AUTHORITY_SHA256,'runtimeEvidenceSha256':'2'*64,
 'runtimeIdentity':runtime,'serviceTransitions':transitions,
 'serviceTransitionsSha256':m.digest(m.canonical(transitions).encode()),'status':'SEALED',
}
recovery={'exportLabels':{m.RECOVERY_LABELS['candidateCommit']:old_commit},'recoveryTag':f'platform/v1-scheduler-recovery:{old_commit}'}
observation={'containers':containers,'schedulerRecovery':recovery}
provenance={'candidateCommit':old_commit,'candidateTree':old_tree,'controllerIdentityProjection':'LEGACY_19','controllerSha256':old_controller,'profile':'CANONICAL_RECONCILED_V1','releaseRoot':authority['releaseRoot'],'sourceArchiveSha256':old_archive}
strict_blocked=False
try: m.validate_external_reconciliation(external,observation)
except m.Stop: strict_blocked=True
state=m.state_document('ACTIVE',observation,'3'*64,'4'*64,1800000100,external,{'status':'fixture'},provenance)
validated=m.validate_state(state,False)
unknown=copy.deepcopy(provenance); unknown['controllerSha256']='0'*63+'1'
unknown_blocked=False
try: m.state_document('ACTIVE',observation,'3'*64,'4'*64,1800000100,external,{'status':'fixture'},unknown)
except m.Stop: unknown_blocked=True
drifted=copy.deepcopy(observation); drifted['containers'][0]['containerId']='f'*64
common_blocked=False
try: m.state_document('ACTIVE',drifted,'3'*64,'4'*64,1800000100,external,{'status':'fixture'},provenance)
except m.Stop: common_blocked=True
print(json.dumps({'commonBlocked':common_blocked,'controlCommit':validated['candidateCommit'],'digestChanged':legacy_digest!=full_digest,'externalCommit':validated['externalAuthorizedReconciliation']['runtimeIdentity']['commit'],'strictBlocked':strict_blocked,'unknownBlocked':unknown_blocked}))
`);
  assert.deepEqual(output, {
    commonBlocked: true,
    controlCommit: "4".repeat(40),
    digestChanged: true,
    externalCommit: "1".repeat(40),
    strictBlocked: true,
    unknownBlocked: true,
  });
});

test("maintenance retry rejects stale checkpoint or recovery before disabling supervisor", () => {
  const output = runPython(String.raw`
import hashlib, importlib.util, json
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
receipt=b"receipt"
checkpoint="a"*64
recovery={"identity":"expected"}
marker={"previousReceiptSha256":hashlib.sha256(receipt).hexdigest(),"rollbackCheckpointSha256":checkpoint,"rollbackSchedulerRecovery":recovery}
m.ensure_private_directory=lambda *_: None
m.os.path.lexists=lambda *_: True
m.reconciliation_status=lambda: marker
m.reconciliation_retains_predecessor_state=lambda *_: True
m.secure_file=lambda *_args,**_kwargs: receipt
calls=[]
m.disable_supervisor=lambda: calls.append("disabled")
blocked=[]
def stale(): raise m.Stop("stale checkpoint")
m.validate_checkpoint=stale
try: m.begin_maintenance()
except m.Stop: blocked.append("stale")
for label,result in (
    ("checkpoint",("b"*64,b"",recovery,{},{})),
    ("recovery",(checkpoint,b"",{"identity":"foreign"},{},{})),
):
    m.validate_checkpoint=lambda result=result: result
    try: m.begin_maintenance()
    except m.Stop: blocked.append(label)
print(json.dumps({"blocked":blocked,"disableCalls":calls}))
`);
  assert.deepEqual(output, { blocked: ["stale", "checkpoint", "recovery"], disableCalls: [] });
});

test("maintenance mutations share one cross-tool lease before controller authority reads", () => {
  const source = fs.readFileSync(controller, "utf8");
  const sudoers = fs.readFileSync(path.join(repositoryRoot, "sudoers/platform-v1-local-private-control"), "utf8");
  assert.match(source, /TRANSACTION_LOCK_FILE = "\/run\/lock\/platform-v1-local-private-transaction\.lock"/);
  assert.match(source, /if arguments\[0\] in \(\s*"abort-maintenance", "aborted-record", "activate", "begin-maintenance",\s*"runtime-authority", "seal", "validation-mode", "verify",\s*\):\s*transaction_lock = acquire_transaction_lock\(\)\s*lock = acquire_lock\(\)\s*try:\s*#.*?configure_exact_release_authority\(\)/s);
  assert.match(sudoers, /^platform_infrastructure ALL=\(root\) NOPASSWD: \/usr\/local\/libexec\/platform-v1-local-private-control verify$/m);
  assert.match(sudoers, /^platform_infrastructure ALL=\(root\) NOPASSWD: \/usr\/local\/libexec\/platform-v1-brownfield-install-consumer install$/m);
});

test("authority-bound read commands take the shared lease before selecting exact evidence", () => {
  const output = runPython(String.raw`
import contextlib, importlib.util, io, json
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
events=[]
m.check_no_stdin=lambda:None
m.initialize=lambda:None
m.acquire_lock=lambda:11
m.os.close=lambda *_:None
m.acquire_transaction_lock=lambda:events.append('transaction-lock') or 12
m.configure_exact_release_authority=lambda:events.append('configure')
m.runtime_authority=lambda:events.append('runtime-authority') or {'schema':'authority'}
m.aborted_record=lambda:events.append('aborted-record') or {'schema':'abort-record'}
m.validation_mode=lambda:events.append('validation-mode') or {'candidateCommit':'1'*40,'schema':'platform.v1-local-private-validation-mode/v1','status':'VALIDATION'}
outputs=[]
for command in ('runtime-authority','aborted-record','validation-mode'):
 stream=io.StringIO()
 with contextlib.redirect_stdout(stream): result=m.main([command])
 outputs.append({'command':command,'document':json.loads(stream.getvalue()),'result':result})
print(json.dumps({'events':events,'outputs':outputs}))
`);
  assert.deepEqual(output, {
    events: [
      "transaction-lock", "configure", "runtime-authority",
      "transaction-lock", "configure", "aborted-record",
      "transaction-lock", "configure", "validation-mode",
    ],
    outputs: [
      { command: "runtime-authority", document: { schema: "authority" }, result: 0 },
      { command: "aborted-record", document: { schema: "abort-record" }, result: 0 },
      { command: "validation-mode", document: { candidateCommit: "1".repeat(40), schema: "platform.v1-local-private-validation-mode/v1", status: "VALIDATION" }, result: 0 },
    ],
  });

  const source = fs.readFileSync(controller, "utf8");
  assert.match(source, /if arguments\[0\] in \(\s*"abort-maintenance", "aborted-record", "activate", "begin-maintenance",\s*"runtime-authority", "seal", "validation-mode", "verify",\s*\):\s*transaction_lock = acquire_transaction_lock\(\)/s);
});

test("validation-mode reports only the exact current candidate mode", () => {
  const output = runPython(String.raw`
import importlib.util, json
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.CANDIDATE_COMMIT='1'*40
m.load_validation_lane=lambda candidate:None
production=m.validation_mode()
m.load_validation_lane=lambda candidate:{'candidateCommit':candidate}
validation=m.validation_mode()
print(json.dumps({'production':production,'validation':validation}))
`);
  assert.deepEqual(output, {
    production: { candidateCommit: "1".repeat(40), schema: "platform.v1-local-private-validation-mode/v1", status: "PRODUCTION" },
    validation: { candidateCommit: "1".repeat(40), schema: "platform.v1-local-private-validation-mode/v1", status: "VALIDATION" },
  });
});

test("runtime authority is selected only after a full ACTIVE verification", () => {
  const output = runPython(String.raw`
import importlib.util, json
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
events=[]
external={'releaseAuthorityDocumentId':'1'*64,'releaseAuthoritySha256':'2'*64}
state={'controller':{},'externalAuthorizedReconciliation':external,'observation':{},'predecessorRuntimeProvenance':{}}
m.verify_active=lambda:events.append('verify-active') or {'status':'ACTIVE'}
m.read_state=lambda *_:events.append('read-state') or state
m.validate_predecessor_runtime_provenance=lambda *_:events.append('validate-provenance')
m.authority_for_external=lambda value:events.append('select-authority') or {'documentId':value['releaseAuthorityDocumentId']}
authority=m.runtime_authority()
print(json.dumps({'authority':authority,'events':events}))
`);
  assert.deepEqual(output, {
    authority: { documentId: "1".repeat(64) },
    events: ["verify-active", "read-state", "validate-provenance", "select-authority"],
  });
});

test("aborted record is exported only from its fully verified ACTIVE binding", () => {
  const output = runPython(String.raw`
import importlib.util, json
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
events=[]
record={'authorityDocumentId':'1'*64,'authoritySha256':'2'*64,'completedAtUnixSeconds':1800000000,'journalSha256':'3'*64,'residualDataMutations':[],'residualDataMutationsSha256':m.digest(m.canonical([]).encode()),'schema':m.ABORT_RECORD_SCHEMA,'status':'ABORTED_NO_DATA_MUTATION','transactionId':'4'*64}
binding={**record,'recordPath':'/fixed/abort.json','recordSha256':m.digest(m.canonical_bytes(record))}
m.verify_active=lambda:events.append('verify-active') or {'status':'ACTIVE'}
m.read_state=lambda *_:events.append('read-state') or {'abortedAuthorizedReconciliation':binding}
m.validate_aborted_reconciliation_binding=lambda value:events.append('validate-binding') or value
m.secure_file=lambda *_args,**_kwargs:events.append('read-record') or m.canonical_bytes(record)
result=m.aborted_record()
print(json.dumps({'events':events,'result':result}))
`);
  assert.deepEqual(output, {
    events: ["verify-active", "read-state", "validate-binding", "read-record"],
    result: {
      authorityDocumentId: "1".repeat(64), authoritySha256: "2".repeat(64), completedAtUnixSeconds: 1_800_000_000,
      journalSha256: "3".repeat(64), residualDataMutations: [], residualDataMutationsSha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
      schema: "platform.v1-local-private-reconciliation-abort-record/v1", status: "ABORTED_NO_DATA_MUTATION", transactionId: "4".repeat(64),
    },
  });
});

test("ACTIVE exports reject every open reconciliation marker before returning evidence", () => {
  const output = runPython(String.raw`
import importlib.util, json
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
events=[]
m.os.path.lexists=lambda path:events.append('marker-exists') or True
m.reconciliation_status=lambda:events.append('validate-marker') or {'status':'RECONCILING'}
m.verify_active=lambda:events.append('verify-active') or {'status':'ACTIVE'}
m.read_state=lambda *_:events.append('read-state') or {}
blocked=[]
for operation in (m.aborted_record,m.runtime_authority):
  try: operation()
  except m.Stop as error: blocked.append(str(error))
print(json.dumps({'blocked':blocked,'events':events}))
`);
  assert.deepEqual(output, {
    blocked: [
      "ACTIVE abort record cannot be exported while a reconciliation is open.",
      "ACTIVE runtime authority cannot be exported while a reconciliation is open.",
    ],
    events: ["marker-exists", "validate-marker", "marker-exists", "validate-marker"],
  });
});

test("historical legacy-dispatcher ACTIVE profile remains closed and verifiable", () => {
  const output = runPython(String.raw`
import importlib.util, json
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
state={'schema':m.STATE_SCHEMA,'observation':{'containers':[{'name':name} for name in m.LEGACY_CONTAINERS]}}
names=m.active_profile_names(state,'fixture')
print(json.dumps({'count':len(names),'legacyDispatcher':m.LEGACY_ALERT_DISPATCHER in names}))
`);
  assert.deepEqual(output, { count: 36, legacyDispatcher: true });
});

test("aborted reconciliation binding exposes exact immutable residual data mutation evidence", () => {
  const output = runPython(String.raw`
import hashlib, importlib.util, json, os, pathlib, tempfile
spec=importlib.util.spec_from_file_location("control", ${JSON.stringify(controller)})
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
root=os.path.realpath(tempfile.mkdtemp(prefix="v1-control-abort-"))
os.chmod(root,0o700); m.TEST_ROOT=root; m.OWNER_UID=os.geteuid(); m.OWNER_GID=os.getegid()
authority_id="a"*64; authority_sha="b"*64
m.EXACT_AUTHORITY={"documentId":authority_id,"authorizedDataMutations":[{"id":"bootstrap-write","service":"control-center","target":"/state/bootstrap","type":"BOOTSTRAP_WRITE"}]}
m.EXACT_AUTHORITY_SHA256=authority_sha
def write(logical,data,mode):
 p=pathlib.Path(root+logical); p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(data); os.chmod(p,mode)
evidence=m.canonical({"status":"PASS"}).encode()+b"\n"; evidence_sha=hashlib.sha256(evidence).hexdigest()
evidence_path=f"{m.STATE_DIR}/data-mutation-evidence/{authority_id}-bootstrap-write-{evidence_sha}.json"
write(evidence_path,evidence,0o444)
residual=[{"authorityId":"bootstrap-write","evidencePath":evidence_path,"evidenceSha256":evidence_sha}]
record={"authorityDocumentId":authority_id,"authoritySha256":authority_sha,"completedAtUnixSeconds":__import__("time").time_ns()//1_000_000_000,"journalSha256":"c"*64,"residualDataMutations":residual,"residualDataMutationsSha256":hashlib.sha256(m.canonical(residual).encode()).hexdigest(),"schema":m.ABORT_RECORD_SCHEMA,"status":"ABORTED_WITH_RESIDUAL_DATA_MUTATIONS","transactionId":"d"*64}
record_bytes=m.canonical(record).encode()+b"\n"; record_sha=hashlib.sha256(record_bytes).hexdigest(); record_path=f"{m.ABORT_RECORD_ARCHIVE_DIR}/{record['transactionId']}-{record_sha}.json"; write(record_path,record_bytes,0o444)
binding={**record,"recordPath":record_path,"recordSha256":record_sha}
valid=m.validate_aborted_reconciliation_binding(binding)
blocked=False
try: m.validate_aborted_reconciliation_binding({**binding,"residualDataMutationsSha256":"e"*64})
except m.Stop: blocked=True
print(json.dumps({"blocked":blocked,"status":valid["status"],"truth":bool(valid["residualDataMutations"])}))
`);
  assert.deepEqual(output, { blocked: true, status: "ABORTED_WITH_RESIDUAL_DATA_MUTATIONS", truth: true });
});

test("controller Docker interface remains observational; reconciliation executor owns mutations", () => {
  const source = fs.readFileSync(controller, "utf8");
  for (const readOnly of ['["info", "--format"', '["inspect", *sorted(ids)]', '["image", "inspect"', '[DOCKER, "ps"']) assert.match(source, new RegExp(readOnly.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.doesNotMatch(source, /\[DOCKER,\s*"(?:compose|create|kill|network|pause|pull|remove|restart|rm|run|start|stop|update|volume)"/);
});

test("authority binds controller, installer, reconciler, sudoers, unit, env descriptor, render and archive", () => {
  const source = fs.readFileSync(controller, "utf8");
  for (const token of ["exact-release-authority.json", "exact-compose.env", "PLATFORM_COMPOSE_VARIANT=LOCAL_PRIVATE", "exact-compose-render.json", "exact-source-archive.tar", '"composeWrapper", "controller", "installer", "reconciler", "sudoers", "unit"']) assert.match(source, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  const validationCheckpointV2 = 'VALIDATION_CHECKPOINT_SCHEMA = "platform.v1-local-private-predeploy-checkpoint-validation/v2"';
  assert.equal(source.split(validationCheckpointV2).length, 2);
  const authoritySurface = source.replace(validationCheckpointV2, "");
  for (const token of ["PINNED_" + "EXACT_MAIN_V1", "/v" + "2", "832bf2baec47055342af" + "7e7f73425444381b91e0"]) assert.equal(authoritySurface.includes(token), false);
});
