#!/usr/bin/python3
"""Read only public helper code and exact public admission pin fields.
Never opens an authority private key, backup passphrase, token or credential file.
"""
import hashlib,json,os,pathlib,re
HELPER=pathlib.Path('/usr/local/libexec/platform-ftps-backup.py')
ADMISSION=pathlib.Path('/home/platform_infrastructure/v1-fresh-runtime/local-private-backup/trust/admission.json')
def main():
 if os.geteuid()!=0:raise RuntimeError('Root required to read protected public source')
 if HELPER.is_symlink() or not HELPER.is_file() or HELPER.stat().st_size>2000000:raise RuntimeError('Unexpected public helper file')
 digest=hashlib.sha256(HELPER.read_bytes()).hexdigest();refs=[];pins=[]
 for p in pathlib.Path('/usr/local/libexec').rglob('*'):
  if p.is_symlink() or not p.is_file() or p.suffix not in ('.py','.mjs','.sh') or p.stat().st_size>3000000:continue
  try:lines=p.read_text().splitlines()
  except UnicodeError:continue
  for number,line in enumerate(lines,1):
   if digest in line:pins.append({'path':str(p),'line':number,'kind':'exact-current-helper-code-pin'})
   if str(HELPER) in line or "helperSha256" in line:
    literals=re.findall(r'[a-f0-9]{64}',line)
    refs.append({'path':str(p),'line':number,'kind':'helper-reference-or-dynamic-pin','literalCodeDigests':literals})
 result={'readOnly':True,'publicHelperPath':str(HELPER),'publicHelperSha256':digest,'exactCodePins':pins,'references':refs}
 if ADMISSION.is_symlink() or not ADMISSION.is_file() or ADMISSION.stat().st_size>1048576:raise RuntimeError('Unexpected public admission file')
 doc=json.loads(ADMISSION.read_text());payload=doc.get('payload',{});pin=payload.get('resources',{}).get('operator',{}).get('helperSha256')
 result['activeAdmission']={'path':str(ADMISSION),'schema':doc.get('schema'),'generation':payload.get('generation'),'field':'payload.resources.operator.helperSha256','publicHelperPin':pin,'matchesLiveHelper':pin==digest}
 print(json.dumps(result,indent=2))
if __name__=='__main__':main()
