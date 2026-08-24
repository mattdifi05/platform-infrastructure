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
transitions=m.reconciliation_service_transitions(records,observation)
runtime={"candidateId":"e"*64,"commit":"f"*40,"deploymentId":"v1-local-private:"+"e"*64,"sourceRenderSha256":"1"*64,"tree":"2"*40,"workloadLockSha256":"3"*64}
legacy=[dict(item) for item in m.LEGACY_UNMANAGED_CONTAINERS]
m.EXACT_AUTHORITY={"authorizedDataMutations":[],"documentId":"a"*64,"legacyNetworkAttachments":[],"legacyUnmanagedContainers":legacy,"runtimeIdentity":runtime}; m.EXACT_AUTHORITY_SHA256="b"*64
external=m.external_reconciliation_document({"beganAtUnixSeconds":1800000000,"legacyUnmanagedContainers":legacy,"previousReceiptDocumentId":"c"*64,"releaseAuthorityDocumentId":"a"*64,"releaseAuthoritySha256":"b"*64,"runtimeIdentity":runtime},"d"*64,transitions,[],[])
print(json.dumps({"statuses":sorted(set(t["status"] for t in transitions)),"containerRecreate":external["containerRecreate"],"dockerMutation":external["externalDockerMutation"],"dataMutation":external["dataMutation"]}))
`);
  assert.deepEqual(output.statuses, ["RETAINED"]);
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
  assert.match(source, /if arguments\[0\] in \("abort-maintenance", "activate", "begin-maintenance", "seal"\):\s*transaction_lock = acquire_transaction_lock\(\)\s*lock = acquire_lock\(\)\s*try:\s*#.*?configure_exact_release_authority\(\)/s);
  assert.match(sudoers, /^platform_infrastructure ALL=\(root\) NOPASSWD: \/usr\/local\/libexec\/platform-v1-local-private-control verify$/m);
  assert.match(sudoers, /^platform_infrastructure ALL=\(root\) NOPASSWD: \/usr\/local\/libexec\/platform-v1-brownfield-install-consumer install$/m);
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
  for (const token of ["PINNED_" + "EXACT_MAIN_V1", "/v" + "2", "832bf2baec47055342af" + "7e7f73425444381b91e0"]) assert.equal(source.includes(token), false);
});
