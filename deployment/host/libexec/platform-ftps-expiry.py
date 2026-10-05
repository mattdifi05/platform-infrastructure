#!/usr/bin/python3
"""Local minute checks; connect only when an authenticated recovery point approaches expiry."""
import importlib.util,json
spec=importlib.util.spec_from_file_location('ftps','/usr/local/libexec/platform-ftps-backup.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
try:
 result=b.expiry_check()
 if result and result.get('status')!='not-due':print(json.dumps(result))
except Exception as error:
 proof={'status':'failed','at':b.now(),'error':str(error)[:300],'trigger':'expiry-only'}
 b.save(b.STATE/'ftps-retention-proof.json',proof,True);print(json.dumps(proof));raise
