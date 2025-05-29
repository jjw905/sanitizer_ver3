import os
from typing import Dict, Any

from utils.feature_extractor import FeatureExtractor
from utils.model_trainer import ModelTrainer


class ModelManager:
    def __init__(self):
        self.trainer = ModelTrainer()
        self.feature_extractor = FeatureExtractor()
        self.model_loaded = False

    def is_model_available(self) -> bool:
        """훈련된 모델이 있는지 확인"""
        return (os.path.exists(self.trainer.model_path) and
                os.path.exists(self.trainer.scaler_path))

    def load_model(self) -> bool:
        """모델 로드"""
        if self.model_loaded:
            return True

        if not self.is_model_available():
            return False

        success = self.trainer.load_model()
        if success:
            self.model_loaded = True

        return success

    def predict_file(self, file_path: str) -> Dict[str, Any]:
        """파일 악성코드 예측"""
        if not self.model_loaded:
            if not self.load_model():
                return {
                    "error": "모델이 로드되지 않았습니다. 먼저 모델을 훈련해주세요.",
                    "prediction": "알 수 없음",
                    "confidence": 0.0
                }

        return self.trainer.predict(file_path)

    def get_model_info(self) -> Dict[str, Any]:
        """모델 정보 반환"""
        info = {
            "model_available": self.is_model_available(),
            "model_loaded": self.model_loaded,
            "model_path": self.trainer.model_path,
            "scaler_path": self.trainer.scaler_path
        }

        if self.is_model_available():
            try:
                # 모델 파일 크기
                model_size = os.path.getsize(self.trainer.model_path)
                scaler_size = os.path.getsize(self.trainer.scaler_path)

                info.update({
                    "model_size_mb": round(model_size / (1024 * 1024), 2),
                    "scaler_size_kb": round(scaler_size / 1024, 2),
                    "model_created": os.path.getctime(self.trainer.model_path)
                })
            except:
                pass

        return info

    def train_new_model(self) -> bool:
        """새 모델 훈련"""
        print("=== 새 모델 훈련 시작 ===")

        # 기존 모델 언로드
        self.model_loaded = False
        self.trainer.ensemble_model = None

        # 새 모델 훈련
        success = self.trainer.train_model()

        if success:
            # 새 모델 로드
            self.load_model()
            print("✅ 새 모델 훈련 및 로드 완료!")
        else:
            print("❌ 모델 훈련 실패")

        return success

    def evaluate_current_model(self):
        """현재 모델 평가"""
        if not self.model_loaded:
            if not self.load_model():
                print("❌ 평가할 모델이 없습니다")
                return

        self.trainer.evaluate_model()

    def get_training_data_status(self) -> Dict[str, int]:
        """훈련 데이터 상태 확인"""
        malware_count = 0
        clean_count = 0

        if os.path.exists("sample/mecro"):
            malware_count = len([
                f for f in os.listdir("sample/mecro")
                if os.path.isfile(os.path.join("sample/mecro", f))
            ])

        if os.path.exists("sample/clear"):
            clean_count = len([
                f for f in os.listdir("sample/clear")
                if os.path.isfile(os.path.join("sample/clear", f))
            ])

        return {
            "malware_samples": malware_count,
            "clean_samples": clean_count,
            "total_samples": malware_count + clean_count,
            "sufficient_data": malware_count >= 10 and clean_count >= 10
        }

    def batch_predict(self, file_paths: list) -> Dict[str, Dict]:
        """다중 파일 예측"""
        if not self.model_loaded:
            if not self.load_model():
                return {"error": "모델을 로드할 수 없습니다"}

        results = {}

        for file_path in file_paths:
            try:
                file_name = os.path.basename(file_path)
                prediction = self.predict_file(file_path)
                results[file_name] = prediction
            except Exception as e:
                results[os.path.basename(file_path)] = {
                    "error": f"예측 실패: {str(e)}"
                }

        return results


# 전역 모델 매니저 인스턴스
model_manager = ModelManager()


def get_model_manager() -> ModelManager:
    """모델 매니저 인스턴스 반환"""
    return model_manager


if __name__ == "__main__":
    # 테스트
    manager = ModelManager()

    print("=== 모델 관리자 테스트 ===")

    # 모델 정보 확인
    info = manager.get_model_info()
    print(f"모델 정보: {info}")

    # 훈련 데이터 상태 확인
    data_status = manager.get_training_data_status()
    print(f"훈련 데이터 상태: {data_status}")

    # 모델이 있으면 테스트 예측
    if manager.is_model_available():
        print("\n모델 로드 테스트...")
        if manager.load_model():
            print("✅ 모델 로드 성공")

            # 샘플 파일로 예측 테스트
            test_files = []
            if os.path.exists("sample/mecro"):
                test_files.extend([
                    os.path.join("sample/mecro", f)
                    for f in os.listdir("sample/mecro")[:2]
                ])

            if test_files:
                print(f"\n{len(test_files)}개 파일 예측 테스트...")
                results = manager.batch_predict(test_files)
                for filename, result in results.items():
                    print(f"{filename}: {result.get('prediction', 'Error')} "
                          f"(신뢰도: {result.get('confidence', 0):.3f})")
        else:
            print("❌ 모델 로드 실패")
    else:
        print("❌ 훈련된 모델이 없습니다")