"""Read-only S3 inventory; never emits keys, object names, or object data."""
import boto3,hashlib,json,os,pathlib
from botocore.config import Config
key=pathlib.Path(os.environ.get('S3_ACCESS_KEY_FILE','/run/s3-secrets/access')).read_text().strip()
secret=pathlib.Path(os.environ.get('S3_SECRET_KEY_FILE','/run/s3-secrets/secret')).read_text().strip()
s=boto3.client('s3',endpoint_url=os.environ.get('S3_ENDPOINT','http://127.0.0.1:9000'),aws_access_key_id=key,aws_secret_access_key=secret,region_name='us-east-1',config=Config(signature_version='s3v4',s3={'addressing_style':'path'},request_checksum_calculation='when_supported',connect_timeout=3,read_timeout=30,retries={'max_attempts':1}))
records=[];buckets=objects=markers=total=0
for b in sorted(x['Name'] for x in s.list_buckets()['Buckets']):
 buckets+=1;status=s.get_bucket_versioning(Bucket=b).get('Status','Disabled');records.append({'bucket':b,'versioning':status})
 for page in s.get_paginator('list_object_versions').paginate(Bucket=b):
  for v in page.get('Versions',[]):
   args={'Bucket':b,'Key':v['Key'],'VersionId':v['VersionId']};g=s.get_object(**args);h=hashlib.sha256();size=0
   while chunk:=g['Body'].read(1024*1024):h.update(chunk);size+=len(chunk)
   records.append({'bucket':b,'key':v['Key'],'version':v['VersionId'],'latest':v['IsLatest'],'sha256':h.hexdigest(),'size':size,'metadata':g.get('Metadata',{}),'contentType':g.get('ContentType'),'tags':s.get_object_tagging(**args)['TagSet']});objects+=1;total+=size
  for v in page.get('DeleteMarkers',[]):records.append({'bucket':b,'key':v['Key'],'version':v['VersionId'],'latest':v['IsLatest'],'deleteMarker':True});markers+=1
canonical=json.dumps(sorted(records,key=lambda r:json.dumps(r,sort_keys=True)),sort_keys=True,separators=(',',':')).encode()
print(json.dumps({'schema':'platform.s3-readonly-inventory/v1','buckets':buckets,'object_versions':objects,'delete_markers':markers,'total_version_bytes':total,'inventory_sha256':hashlib.sha256(canonical).hexdigest()}))
