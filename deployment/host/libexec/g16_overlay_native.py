"""Forward-generation native dispatch for a typed source-metadata overlay.

Loaded by the copied FTPS helper only. It has no network or host side effects
at import time; callers pass the helper namespace for explicit monkey-patch
installation. Production g15 files are not changed.
"""
import datetime
import hashlib
import hmac
import importlib.util
import json
import os
import pathlib
import re
import stat
import sys
import time

G16_SCHEMA = "platform.ftps-source-metadata-overlay/v4"
G16_KIND = "source-metadata-overlay-v4"
G16_PART_BYTES = 250_000_000
G16_MAX_PARTS = 70
G16_MAX_FILES = 4
G16_MEMBER_NAMES = {"receipt.json", "metadata/records.ndjson.gz", "host-capsule/current.gpg",
                    "mounted-config/records.json"}
G16_MAX_INDEX_RAW = 512 * 1024 * 1024
METADATA_MODULE_SHA256 = "30bfde6ae7d68d8ed22f016e67f2bf23f2bbc79933b6047f4201eed536cdd79d"
MOUNTED_CONFIG_MODULE_SHA256 = "adc2406fba1cce0aa4086cc15cd50ac76411c8f4b144cbe33cb8284e1dcda99a"


def _load_metadata_module():
    path = pathlib.Path(__file__).absolute().with_name("source_metadata_overlay_v3.py")
    info = path.lstat()
    if (path.is_symlink() or path.resolve() != path or not stat.S_ISREG(info.st_mode) or
            info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1):
        raise RuntimeError("source metadata module path or ownership differs")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != METADATA_MODULE_SHA256:
        raise RuntimeError("source metadata module pin differs")
    spec = importlib.util.spec_from_file_location("source_metadata_overlay_v3", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("source metadata module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_mounted_config_module():
    path = pathlib.Path(__file__).absolute().with_name("mounted_config_sidecar_v5.py")
    info = path.lstat()
    if (path.is_symlink() or path.resolve() != path or not stat.S_ISREG(info.st_mode) or
            info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1):
        raise RuntimeError("mounted-config module path or ownership differs")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != MOUNTED_CONFIG_MODULE_SHA256:
        raise RuntimeError("mounted-config module pin differs")
    spec = importlib.util.spec_from_file_location("mounted_config_sidecar_v5", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("mounted-config module cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _parent_binding(b, payload, parent):
    expected = {
        "parentManifestId": parent["manifestId"],
        "parentManifestDigest": parent["manifestDigest"],
        "parentReceiptSha256": hashlib.sha256(b.canonical(b.sign(parent))).hexdigest(),
        "parentEncryptedSha256": parent["encryptedSha256"],
        "backupAt": parent["backupAt"],
    }
    if any(payload.get(k) != v for k, v in expected.items()):
        raise RuntimeError("Source overlay parent binding differs")


def verify_g16(b, document, parent, staged=False):
    if len(b.canonical(document)) > b.SUPPLEMENT_RECEIPT_LIMIT:
        raise RuntimeError("Source overlay receipt exceeds bound")
    if set(document) != {"payload", "hmacSha256"} or not hmac.compare_digest(
            b.sign_supplement(document.get("payload"))['hmacSha256'], document.get("hmacSha256", "")):
        raise RuntimeError("Source overlay HMAC differs")
    p = document["payload"]
    fields = {
        "schema", "status", "kind", "parentManifestId", "parentManifestDigest", "parentReceiptSha256",
        "parentEncryptedSha256", "backupAt", "ciphertext", "encryptedBytes", "encryptedSha256", "parts",
        "verifiedAt", "fullyRecoverable", "knownGaps", "baseCompletenessCiphertext",
        "baseCompletenessEncryptedSha256", "baseCompletenessReceiptSha256", "baseArchiveSha256", "baseArchiveBytes", "overlayPackageSha256",
        "overlayReceiptSha256", "sourceMapSha256", "metadataIndexSha256", "metadataIndexRawSha256",
        "metadataIndexCompressedBytes", "metadataIndexRawBytes", "metadataRecordCount", "capsuleSha256",
        "capsuleProofSha256", "files", "mountedConfigCapture",
    }
    if set(p) != fields or p["schema"] != G16_SCHEMA or p["status"] != "passed" or p["kind"] != G16_KIND:
        raise RuntimeError("Invalid source overlay schema")
    _parent_binding(b, p, parent)
    if p["fullyRecoverable"] is not False:
        raise RuntimeError("Source overlay cannot assert whole-stack recovery")
    if not isinstance(p["knownGaps"], list) or not 1 <= len(p["knownGaps"]) <= 128:
        raise RuntimeError("Explicit source overlay scope gaps required")
    for key in ("encryptedSha256", "baseCompletenessEncryptedSha256", "baseCompletenessReceiptSha256",
                "overlayPackageSha256", "overlayReceiptSha256", "sourceMapSha256", "metadataIndexSha256",
                "metadataIndexRawSha256", "capsuleSha256", "capsuleProofSha256", "baseArchiveSha256"):
        if not isinstance(p[key], str) or not re.fullmatch("[a-f0-9]{64}", p[key]):
            raise RuntimeError("Source overlay digest binding invalid")
    if p["baseCompletenessCiphertext"] != parent["bundle"] + ".supplement-full-" + p["baseCompletenessEncryptedSha256"][:16] + ".tar.gpg":
        raise RuntimeError("Source overlay base completeness name invalid")
    if type(p["baseArchiveBytes"]) is not int or not 0 < p["baseArchiveBytes"] <= b.CAP:
        raise RuntimeError("Source overlay base archive size invalid")
    if p["ciphertext"] != parent["bundle"] + ".supplement-source-v4-" + p["encryptedSha256"][:16] + ".tar.gz.gpg":
        raise RuntimeError("Source overlay ciphertext name invalid")
    if type(p["encryptedBytes"]) is not int or not 0 < p["encryptedBytes"] <= b.CAP:
        raise RuntimeError("Source overlay encrypted size exceeds cap")
    if type(p["metadataIndexCompressedBytes"]) is not int or not 0 < p["metadataIndexCompressedBytes"] <= b.CAP:
        raise RuntimeError("Source overlay compressed index bound invalid")
    if type(p["metadataIndexRawBytes"]) is not int or not 0 < p["metadataIndexRawBytes"] <= G16_MAX_INDEX_RAW:
        raise RuntimeError("Source overlay raw index bound invalid")
    if type(p["metadataRecordCount"]) is not int or not 57 <= p["metadataRecordCount"] <= 1_000_000:
        raise RuntimeError("Source overlay record bound invalid")
    if not staged:
        try:
            stamp = datetime.datetime.fromisoformat(p["verifiedAt"].replace("Z", "+00:00")).timestamp()
        except (AttributeError, TypeError, ValueError):
            raise RuntimeError("Source overlay verification timestamp invalid")
        if stamp > time.time() + 300:
            raise RuntimeError("Source overlay verification timestamp is in future")
    elif p["verifiedAt"] is not None and not isinstance(p["verifiedAt"], str):
        raise RuntimeError("Staged source overlay timestamp invalid")
    parts = p["parts"]
    if not isinstance(parts, list) or not 1 <= len(parts) <= G16_MAX_PARTS:
        raise RuntimeError("Source overlay multipart count invalid")
    seen_parts = set(); total = 0
    for i, item in enumerate(parts):
        expected_name = p["ciphertext"] + ".part" + str(i).zfill(3)
        if (set(item) != {"name", "bytes", "sha256"} or item["name"] != expected_name or
            type(item["bytes"]) is not int or not 0 < item["bytes"] <= b.PART_BYTES or
            not re.fullmatch("[a-f0-9]{64}", str(item["sha256"])) or item["name"] in seen_parts):
            raise RuntimeError("Source overlay ordered part binding invalid")
        seen_parts.add(item["name"]); total += item["bytes"]
    if total != p["encryptedBytes"]:
        raise RuntimeError("Source overlay multipart total differs")
    files = p["files"]
    if not isinstance(files, list) or len(files) != G16_MAX_FILES:
        raise RuntimeError("Source overlay exact four-member list required")
    by_name = {}
    for item in files:
        if (not isinstance(item, dict) or set(item) != {"name", "bytes", "sha256"} or
            item["name"] not in G16_MEMBER_NAMES or type(item["bytes"]) is not int or item["bytes"] < 0 or
            not re.fullmatch("[a-f0-9]{64}", str(item["sha256"])) or item["name"] in by_name):
            raise RuntimeError("Source overlay member binding invalid")
        by_name[item["name"]] = item
    sidecar = p["mountedConfigCapture"]
    if (not isinstance(sidecar, dict) or set(sidecar) != {"member", "bytes", "sha256", "cycleId",
            "catalogSha256", "planSha256", "sourceCount", "recordCount", "providerCounts"} or
            sidecar.get("member") != "mounted-config/records.json" or type(sidecar.get("bytes")) is not int or
            not 0 < sidecar["bytes"] <= 512 * 1024 * 1024 or
            not re.fullmatch("[a-f0-9]{64}", str(sidecar.get("sha256", ""))) or
            sidecar.get("sourceCount") != 89 or type(sidecar.get("recordCount")) is not int or
            not 89 <= sidecar["recordCount"] <= 1_000_000 or
            sidecar.get("catalogSha256") != "f5cea1410282bcf5df8b722b11b7e1ccb67cc497c5fc401bab549152b5b52e69" or
            sidecar.get("planSha256") != "c6f09fd00d7f8a7e1dc8794e214dfec1f0bf48f663fec2b0f26b8575b34d4c29" or
            sidecar.get("providerCounts") != {"parent-capsule-exact-binding": 76,
                "fresh-capsule-regular-file": 8, "authenticated-students-secret-file": 5} or
            not isinstance(sidecar.get("cycleId"), str) or not sidecar["cycleId"]):
        raise RuntimeError("Mounted-config sidecar descriptor invalid")
    if (set(by_name) != G16_MEMBER_NAMES or
            by_name["metadata/records.ndjson.gz"]["bytes"] != p["metadataIndexCompressedBytes"] or
            by_name["mounted-config/records.json"] != {"name": sidecar["member"],
                "bytes": sidecar["bytes"], "sha256": sidecar["sha256"]}):
        raise RuntimeError("Source overlay member set/index size differs")
    return p


def g16_objects(b, p):
    parts = p.get("parts")
    if not isinstance(parts, list) or not 1 <= len(parts) <= G16_MAX_PARTS:
        raise RuntimeError("Source overlay parts missing")
    result = {}
    for i, part in enumerate(parts):
        name = p["ciphertext"] + ".part" + str(i).zfill(3)
        if part.get("name") != name or type(part.get("bytes")) is not int:
            raise RuntimeError("Source overlay part name invalid")
        result[name] = part["bytes"]
    if sum(result.values()) != p["encryptedBytes"]:
        raise RuntimeError("Source overlay part bytes differ")
    return result


def install(namespace):
    """Install dispatch in an isolated g16 candidate helper module namespace."""
    b = type("BackupHelperNamespace", (), {})()
    b.__dict__.update(namespace)
    sys.path.insert(0, str(pathlib.Path(namespace["__file__"]).resolve().parent))
    original_verify = namespace["verify_supplement"]
    original_objects = namespace["supplement_objects"]
    original_validate = namespace["validate_supplement_set"]
    original_points = namespace["point_supplements"]
    original_restore_archive = namespace["restore_supplement_archive"]

    def verify_supplement(document, parent, staged=False):
        if document.get("payload", {}).get("schema") == G16_SCHEMA:
            return verify_g16(b, document, parent, staged)
        return original_verify(document, parent, staged)

    def supplement_objects(payload):
        if payload.get("schema") == G16_SCHEMA: return g16_objects(b, payload)
        return original_objects(payload)

    def validate_supplement_set(items):
        kinds = [item["kind"] for item in items]
        allowed = {"host-recovery-helper-delta", "runtime-completeness-material", G16_KIND}
        if len(kinds) > 3 or len(kinds) != len(set(kinds)) or not set(kinds) <= allowed:
            raise RuntimeError("Duplicate or unsupported supplement kind")
        overlays = [i for i in items if i["kind"] == G16_KIND]
        if overlays:
            bases = [i for i in items if i["kind"] == "runtime-completeness-material"]
            if len(overlays) != 1 or len(bases) != 1:
                raise RuntimeError("Source overlay requires exactly one full-runtime completeness base")
            overlay, base = overlays[0], bases[0]
            base_receipt = hashlib.sha256(b.canonical(b.sign_supplement(base))).hexdigest()
            archives=[m for m in base.get("files",[]) if m.get("name")=="full-runtime.tar.gz"]
            if (len(archives)!=1 or overlay["baseArchiveSha256"]!=archives[0].get("sha256") or
                overlay["baseArchiveBytes"]!=archives[0].get("bytes") or
                overlay["baseCompletenessCiphertext"] != base["ciphertext"] or
                overlay["baseCompletenessEncryptedSha256"] != base["encryptedSha256"] or
                overlay["baseCompletenessReceiptSha256"] != base_receipt):
                raise RuntimeError("Source overlay is bound to a different completeness base")

    def point_supplements(f, listing, confirmed):
        # The g15 parser validates after each receipt. Give it a deterministic
        # receipt order so an MLSD response that lists the overlay first cannot
        # make a valid base+overlay point look incomplete.
        order = {"host-recovery-helper-delta": 0, "runtime-completeness-material": 1, G16_KIND: 2}
        receipts=[]
        for name,size in listing.items():
            if name.endswith('.receipt.json') and '.supplement-' in name:
                document=b.get_json(f,name,b.SUPPLEMENT_RECEIPT_LIMIT)
                kind=document.get('payload',{}).get('kind')
                receipts.append((order.get(kind,99),name,size))
        receipt_names={name for _,name,_ in receipts}
        ordered={name:size for name,size in listing.items() if name not in receipt_names}
        for _,name,size in sorted(receipts):ordered[name]=size
        result = original_points(f, ordered, confirmed)
        for bundle in result:
            result[bundle].sort(key=lambda p: order[p["kind"]])
        return result

    def restore_supplement_archive(plain, destination, payload):
        if payload.get("schema") != G16_SCHEMA:
            return original_restore_archive(plain, destination, payload)
        # The GPG plaintext is the exact deterministic four-member V5 package.
        from pathlib import Path
        import importlib.util
        metadata_module = _load_metadata_module()
        mounted_module = _load_mounted_config_module()
        destination = Path(destination)
        destination.mkdir(mode=0o700, exist_ok=False)
        if b.sha(plain) != payload["overlayPackageSha256"]:
            raise RuntimeError("Source overlay package SHA differs")
        read_result = mounted_module.read_v5_package(
            plain, metadata_out=destination / "metadata.records.ndjson.gz",
            capsule_out=destination / "host-capsule.current.gpg",
            sidecar_out=destination / "mounted-config.records.json", hmac_key=b.KEY.read_bytes(),
            base_module=metadata_module, expected_parent=payload["parentManifestDigest"],
            expected_base_cipher=payload["baseCompletenessEncryptedSha256"],
            expected_base_receipt=payload["baseCompletenessReceiptSha256"],
            expected_archive_sha256=payload["baseArchiveSha256"],
            expected_archive_bytes=payload["baseArchiveBytes"])
        if not isinstance(read_result,tuple) or len(read_result)!=4:
            raise RuntimeError("Source overlay reader did not return a native membership derivation")
        receipt,sidecar_doc,package_rows,source_resource_ids=read_result
        inner = receipt["payload"]
        expiry = inner["sourceCapture"]["expiredDerivedCacheFiles"]
        if expiry == []:
            expiry_valid = inner["sourceCapture"].get("byteInvariant") == "exact-v1-path-type-bytes-symlink-targets"
        else:
            expiry_valid = (isinstance(expiry, dict) and
                expiry.get("catalogSha256") == metadata_module.EXPIRATION_CATALOG_SHA256 and
                len(expiry.get("entries", [])) == metadata_module.EXPIRATION_COUNT)
        sidecar_bytes=(destination / "mounted-config.records.json").read_bytes()
        mounted_module.verify_binding(payload, payload["files"], sidecar_bytes, sidecar_doc)
        if package_rows != payload["files"]:
            raise RuntimeError("Native package member index differs from the signed outer receipt")
        if (not expiry_valid or
            hashlib.sha256(b.canonical(receipt)).hexdigest() != payload["overlayReceiptSha256"] or
            inner["sourceCapture"]["sourceMapSha256"] != payload["sourceMapSha256"] or
            inner["metadataIndex"]["sha256"] != payload["metadataIndexSha256"] or
            inner["metadataIndex"]["rawSha256"] != payload["metadataIndexRawSha256"] or
            inner["metadataIndex"]["compressedBytes"] != payload["metadataIndexCompressedBytes"] or
            inner["metadataIndex"]["rawBytes"] != payload["metadataIndexRawBytes"] or
            inner["metadataIndex"]["recordCount"] != payload["metadataRecordCount"] or
            inner["capsule"]["ciphertextSha256"] != payload["capsuleSha256"] or
            inner["capsule"]["proofSha256"] != payload["capsuleProofSha256"] or
            inner["base"]["archiveSha256"] != payload["baseArchiveSha256"] or
                inner["base"]["archiveBytes"] != payload["baseArchiveBytes"] or
                payload["mountedConfigCapture"].get("cycleId") != sidecar_doc.get("cycleId")):
            raise RuntimeError("Source overlay inner/outer bindings differ")
        capsule_work = destination / "capsule-verify"
        capsule_work.mkdir(mode=0o700)
        short_gpg_home = mounted_module.short_gpg_home_path()
        capsule_result = mounted_module.decrypt_and_verify_capsule(
            destination / "host-capsule.current.gpg", sidecar_bytes, sidecar_doc,
            short_gpg_home, payload["capsuleSha256"])
        return {"status": "passed", "files": 4, "bytes": plain.stat().st_size,
                "overlayPackageSha256": payload["overlayPackageSha256"], "metadataIndexSha256": payload["metadataIndexSha256"],
                "innerTypedReceiptSha256": hashlib.sha256(metadata_module.canonical(receipt)).hexdigest(),
                "metadataValidated": True, "capsuleCiphertextSha256": payload["capsuleSha256"],
                "mountedConfigModuleCodeSha256": hashlib.sha256(Path(mounted_module.__file__).read_bytes()).hexdigest(),
                "mountedConfigSidecarSha256": hashlib.sha256(sidecar_bytes).hexdigest(),
                "mountedConfigCycleId": sidecar_doc["cycleId"], "mountedConfigCapsuleReadback": capsule_result,
                "sourceResourceIds": source_resource_ids,
                "nativeReaderCodeSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "sourceMetadataReaderCodeSha256": hashlib.sha256(Path(metadata_module.__file__).read_bytes()).hexdigest(),
                "automaticMetadataApplication": False, "fullyRecoverable": False}

    namespace["verify_supplement"] = verify_supplement
    namespace["supplement_objects"] = supplement_objects
    namespace["validate_supplement_set"] = validate_supplement_set
    namespace["point_supplements"] = point_supplements
    namespace["restore_supplement_archive"] = restore_supplement_archive
