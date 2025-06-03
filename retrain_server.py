# retrain_server.py
from fastapi import FastAPI
import subprocess
from fastapi.responses import JSONResponse
from datetime import datetime

app = FastAPI()

@app.post("/train")
def train_model():
    try:
        print("[INFO] 훈련 시작")
        subprocess.run(["python3", "-m", "utils.model_trainer"], check=True)

        # 메타 정보 읽기
        import json
        with open("models/model_meta.json") as f:
            meta = json.load(f)

        return {
            "status": "success",
            "trained_at": meta.get("trained_at"),
            "accuracy": meta.get("accuracy"),
            "malware_samples": meta.get("malware_samples"),
            "clean_samples": meta.get("clean_samples"),
            "total_samples": meta.get("total_samples"),
            "model_version": meta.get("model_version")
        }

    except subprocess.CalledProcessError:
        return JSONResponse(status_code=500, content={"status": "error", "message": "학습 실패"})
