import os, boto3
import config

s3 = boto3.client("s3", region_name=config.AWS_REGION)

def upload(local, key):
    if not config.USE_AWS: return
    s3.upload_file(local, config.S3_BUCKET, key)

def download(key, local):
    if not config.USE_AWS: return
    if not os.path.exists(local):
        os.makedirs(os.path.dirname(local), exist_ok=True)
        s3.download_file(config.S3_BUCKET, key, local)
