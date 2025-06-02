import hashlib
import boto3
import config
import os
import json
from datetime import timezone

s3 = boto3.client("s3", region_name=config.AWS_REGION)

def download(key, local):
    if not config.USE_AWS:
        print("[AWS] USE_AWS=false → 다운로드 생략")
        return
    try:
        print(f"[AWS] S3 → {local} 다운로드 시도")
        s3.download_file(config.S3_BUCKET, key, local)
        print("[AWS] 다운로드 완료")
    except Exception as e:
        print(f"[AWS] 다운로드 실패: {e}")

def get_s3_model_info(key: str = "models/ensemble_model.pkl"):
    """S3 객체 메타데이터 + SHA256 해시 + 학습 메타 정보(model_meta.json) 반환"""
    try:
        # 1) S3에서 모델 파일 head 요청
        response = s3.head_object(Bucket=config.S3_BUCKET, Key=key)
        size_bytes = response['ContentLength']
        last_modified = response['LastModified'].astimezone(timezone.utc)

        # 2) 모델 파일 다운로드 후 SHA256 해시 계산
        tmp_model = f"_tmp_{os.path.basename(key)}"
        s3.download_file(config.S3_BUCKET, key, tmp_model)

        with open(tmp_model, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        os.remove(tmp_model)

        # 3) model_meta.json 다운로드 시도
        meta = None
        tmp_meta = "_tmp_model_meta.json"
        try:
            s3.download_file(config.S3_BUCKET, "models/model_meta.json", tmp_meta)
            with open(tmp_meta, "r") as f:
                meta = json.load(f)
            os.remove(tmp_meta)
        except Exception as meta_err:
            meta = {"error": f"model_meta.json 로드 실패: {str(meta_err)}"}

        return {
            "size_mb": round(size_bytes / 1024 / 1024, 2),
            "last_modified": last_modified.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "sha256": sha256,
            "meta": meta
        }

    except Exception as e:
        return {"error": str(e)}
