import os
import pickle
from typing import Dict, Any
from datetime import datetime

from utils.feature_extractor import FeatureExtractor
from utils.model_trainer import ModelTrainer
from config import DATA_SUFFICIENCY


class ModelManager:
    def __init__(self):
        self.trainer = ModelTrainer()
        self.feature_extractor = FeatureExtractor()
        self.model_loaded = False
        self.model_metadata = {}

    def is_model_available(self) -> bool:
        """훈련된 모델 존재 확인 (300개 이상 기준)"""
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
            self._load_metadata()

        return success

    def _load_metadata(self):
        """모델 메타데이터 로드"""
        try:
            metadata_path = "models/model_metadata.pkl"
            if os.path.exists(metadata_path):
                with open(metadata_path, 'rb') as f:
                    self.model_metadata = pickle.load(f)
        except Exception as e:
            print(f"메타데이터 로드 실패: {e}")
            self.model_metadata = {}

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
                # 파일 크기 계산
                model_size = os.path.getsize(self.trainer.model_path)
                scaler_size = os.path.getsize(self.trainer.scaler_path)

                info.update({
                    "model_size_mb": round(model_size / (1024 * 1024), 2),
                    "scaler_size_kb": round(scaler_size / 1024, 2),
                    "model_created": datetime.fromtimestamp(
                        os.path.getctime(self.trainer.model_path)
                    ).strftime('%Y-%m-%d %H:%M:%S')
                })

                # 메타데이터 정보 추가
                if self.model_metadata:
                    info.update({
                        "training_samples": self.model_metadata.get('total_training_samples', 0),
                        "model_accuracy": self.model_metadata.get('accuracy', 0),
                        "training_date": self.model_metadata.get('training_date', 'Unknown'),
                        "model_version": self.model_metadata.get('version', '1.0'),
                        "update_count": self.model_metadata.get('update_count', 0),
                        "last_updated": self.model_metadata.get('last_updated', 'Never')
                    })

            except Exception as e:
                print(f"모델 정보 수집 오류: {e}")

        return info

    def update_model_with_new_data(self) -> bool:
        """기존 모델을 새로운 데이터로 업데이트"""
        print("=== 모델 업데이트 시작 ===")

        try:
            # 새로운 데이터 수집
            print("단계 1: 새로운 샘플 수집 중...")
            from utils.api_client import collect_additional_training_data
            new_sample_count = collect_additional_training_data(target_count=100)

            if new_sample_count == 0:
                print("⚠️ 새로운 샘플을 수집하지 못했습니다.")
                return False

            # 모델 재훈련 (기존 + 새 데이터)
            print("단계 2: 모델 업데이트 훈련 중...")
            success = self.trainer.train_model()

            if success:
                # 메타데이터 업데이트
                self._update_metadata(new_sample_count)
                print("✅ 모델 업데이트 완료!")

                # 업데이트된 모델 다시 로드
                self.model_loaded = False
                self.load_model()
            else:
                print("❌ 모델 업데이트 실패")

            return success

        except Exception as e:
            print(f"❌ 모델 업데이트 중 오류: {e}")
            return False

    def _update_metadata(self, new_sample_count: int):
        """메타데이터 업데이트"""
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if not self.model_metadata:
            self.model_metadata = {
                'version': '1.0',
                'update_count': 0,
                'total_training_samples': 0
            }

        # 업데이트 정보 갱신
        self.model_metadata.update({
            'last_updated': current_time,
            'update_count': self.model_metadata.get('update_count', 0) + 1,
            'total_training_samples': self.model_metadata.get('total_training_samples', 0) + new_sample_count,
            'version': f"1.{self.model_metadata.get('update_count', 0) + 1}"
        })

        # 메타데이터 저장
        try:
            metadata_path = "models/model_metadata.pkl"
            with open(metadata_path, 'wb') as f:
                pickle.dump(self.model_metadata, f)
        except Exception as e:
            print(f"메타데이터 저장 실패: {e}")

    def train_new_model(self) -> bool:
        """새 모델 훈련 (300개 이상 데이터 기준)"""
        print("=== 새 모델 훈련 시작 ===")

        # 기존 모델 언로드
        self.model_loaded = False
        self.trainer.ensemble_model = None

        # 새 모델 훈련
        success = self.trainer.train_model()

        if success:
            # 메타데이터 생성
            self._create_initial_metadata()

            # 새 모델 로드
            self.load_model()
            print("✅ 새 모델 훈련 및 로드 완료!")
        else:
            print("❌ 모델 훈련 실패")

        return success

    def _create_initial_metadata(self):
        """초기 메타데이터 생성"""
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        data_status = self.get_training_data_status()

        self.model_metadata = {
            'version': '1.0',
            'training_date': current_time,
            'last_updated': current_time,
            'update_count': 0,
            'total_training_samples': data_status['total_samples'],
            'accuracy': 0.0,
            'model_type': 'ensemble'
        }

        # 메타데이터 저장
        try:
            metadata_path = "models/model_metadata.pkl"
            with open(metadata_path, 'wb') as f:
                pickle.dump(self.model_metadata, f)
        except Exception as e:
            print(f"메타데이터 생성 실패: {e}")

    def evaluate_current_model(self):
        """현재 모델 평가"""
        if not self.model_loaded:
            if not self.load_model():
                print("❌ 평가할 모델이 없습니다")
                return

        self.trainer.evaluate_model()

    def get_training_data_status(self) -> Dict[str, int]:
        """훈련 데이터 상태 확인 (300개 이상 기준)"""
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

        total_samples = malware_count + clean_count

        # 새로운 충분성 기준 (300개 이상)
        sufficient_data = (
                malware_count >= DATA_SUFFICIENCY['minimum_malware_samples'] and
                clean_count >= DATA_SUFFICIENCY['minimum_clean_samples'] and
                total_samples >= DATA_SUFFICIENCY['minimum_total_samples']
        )

        return {
            "malware_samples": malware_count,
            "clean_samples": clean_count,
            "total_samples": total_samples,
            "sufficient_data": sufficient_data,
            "recommended_total": DATA_SUFFICIENCY['recommended_training_size'],
            "sufficiency_percentage": round((total_samples / DATA_SUFFICIENCY['minimum_total_samples']) * 100, 1)
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

    def get_model_performance_history(self) -> Dict[str, Any]:
        """모델 성능 히스토리 반환"""
        if not self.model_metadata:
            return {"error": "메타데이터 없음"}

        return {
            "model_version": self.model_metadata.get('version', '1.0'),
            "update_count": self.model_metadata.get('update_count', 0),
            "training_date": self.model_metadata.get('training_date', 'Unknown'),
            "last_updated": self.model_metadata.get('last_updated', 'Never'),
            "total_training_samples": self.model_metadata.get('total_training_samples', 0),
            "current_accuracy": self.model_metadata.get('accuracy', 0),
            "model_type": self.model_metadata.get('model_type', 'ensemble')
        }

    def check_model_health(self) -> Dict[str, Any]:
        """모델 상태 건강성 체크"""
        health_status = {
            "model_exists": self.is_model_available(),
            "model_loadable": False,
            "data_sufficient": False,
            "performance_acceptable": False,
            "needs_update": False,
            "issues": [],
            "recommendations": []
        }

        # 모델 로드 가능성 체크
        if health_status["model_exists"]:
            health_status["model_loadable"] = self.load_model()

            if not health_status["model_loadable"]:
                health_status["issues"].append("모델 로드 실패")
                health_status["recommendations"].append("모델 재훈련 필요")

        # 데이터 충분성 체크
        data_status = self.get_training_data_status()
        health_status["data_sufficient"] = data_status["sufficient_data"]

        if not health_status["data_sufficient"]:
            health_status["issues"].append(
                f"훈련 데이터 부족 ({data_status['total_samples']}/{DATA_SUFFICIENCY['minimum_total_samples']})")
            health_status["recommendations"].append("추가 샘플 수집 필요")

        # 성능 체크
        if self.model_metadata:
            accuracy = self.model_metadata.get('accuracy', 0)
            if accuracy > 0.85:
                health_status["performance_acceptable"] = True
            else:
                health_status["issues"].append(f"모델 정확도 낮음 ({accuracy:.3f})")
                health_status["recommendations"].append("모델 재훈련 또는 데이터 품질 개선")

            # 업데이트 필요성 체크 (30일 이상)
            last_updated = self.model_metadata.get('last_updated', '')
            if last_updated:
                try:
                    from datetime import datetime, timedelta
                    last_update_date = datetime.strptime(last_updated, '%Y-%m-%d %H:%M:%S')
                    if datetime.now() - last_update_date > timedelta(days=30):
                        health_status["needs_update"] = True
                        health_status["recommendations"].append("30일 이상 업데이트되지 않음 - 최신 데이터로 업데이트 권장")
                except:
                    pass

        # 전체 상태 평가
        if health_status["model_exists"] and health_status["model_loadable"] and health_status["data_sufficient"]:
            health_status["overall_status"] = "양호"
        elif health_status["model_exists"] and health_status["model_loadable"]:
            health_status["overall_status"] = "보통"
        else:
            health_status["overall_status"] = "불량"

        return health_status


# 전역 모델 매니저 인스턴스
model_manager = ModelManager()


def get_model_manager() -> ModelManager:
    """모델 매니저 인스턴스 반환"""
    return model_manager


if __name__ == "__main__":
    # 간단 테스트
    manager = ModelManager()

    print("=== 모델 관리자 테스트 ===")

    # 데이터 상태 확인
    data_status = manager.get_training_data_status()
    print(f"훈련 데이터: 악성 {data_status['malware_samples']}개, 정상 {data_status['clean_samples']}개")
    print(f"충분성: {data_status['sufficiency_percentage']}% ({'충분' if data_status['sufficient_data'] else '부족'})")

    # 모델 상태 확인
    if manager.is_model_available():
        print("✅ 모델 사용 가능")
        if manager.load_model():
            print("✅ 모델 로드 성공")
        else:
            print("❌ 모델 로드 실패")
    else:
        print("❌ 훈련된 모델 없음")
        if data_status['sufficient_data']:
            print("💡 충분한 데이터 있음 - 모델 훈련 가능")
        else:
            print(f"💡 {DATA_SUFFICIENCY['minimum_total_samples'] - data_status['total_samples']}개 샘플 더 필요")