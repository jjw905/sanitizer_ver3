# utils/model_manager.py - 개선된 버전 (증분 학습 지원)

import os
from typing import Dict, Any

from utils.feature_extractor import FeatureExtractor
from utils.model_trainer import ModelTrainer


class ModelManager:
    def __init__(self):
        self.trainer = ModelTrainer()
        self.feature_extractor = FeatureExtractor()
        self.model_loaded = False

        # 지원 파일 형식 정의
        self.supported_extensions = {'.hwp', '.hwpx', '.docx', '.docm', '.pdf', '.pptx', '.pptm', '.xlsx', '.xlsm'}

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
        """파일 악성코드 예측 (지원 형식만)"""
        # 파일 형식 확인
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.supported_extensions:
            return {
                "error": f"지원되지 않는 파일 형식: {ext}",
                "prediction": "알 수 없음",
                "confidence": 0.0,
                "supported_formats": list(self.supported_extensions)
            }

        # 모델 로드 확인
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
            "scaler_path": self.trainer.scaler_path,
            "supported_formats": list(self.supported_extensions)
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

                # 훈련 기록 정보 추가
                if os.path.exists(self.trainer.training_history_path):
                    history_size = os.path.getsize(self.trainer.training_history_path)
                    info.update({
                        "training_history_available": True,
                        "history_size_kb": round(history_size / 1024, 2)
                    })
                else:
                    info["training_history_available"] = False

            except Exception as e:
                info["file_info_error"] = str(e)

        return info

    def train_new_model(self, incremental=True) -> bool:
        """새 모델 훈련 (증분 학습 또는 전체 학습)"""
        print(f"=== 모델 {'업데이트 (증분 학습)' if incremental else '전체 훈련'} 시작 ===")

        # 기존 모델 언로드
        self.model_loaded = False
        self.trainer.ensemble_model = None

        # 훈련 방식 선택
        if incremental and self.is_model_available():
            # 증분 학습
            success = self.trainer.incremental_train_model()
        else:
            # 전체 학습
            success = self.trainer.train_model()

        if success:
            # 새 모델 로드
            self.load_model()
            print(f"✅ 모델 {'업데이트' if incremental else '훈련'} 및 로드 완료!")
        else:
            print(f"❌ 모델 {'업데이트' if incremental else '훈련'} 실패")

        return success

    def evaluate_current_model(self):
        """현재 모델 평가"""
        if not self.model_loaded:
            if not self.load_model():
                print("❌ 평가할 모델이 없습니다")
                return

        self.trainer.evaluate_model()

    def get_training_data_status(self) -> Dict[str, int]:
        """훈련 데이터 상태 확인 (지원 형식만)"""
        malware_count = 0
        clean_count = 0

        # 악성 샘플 카운트 (지원 형식만)
        if os.path.exists("sample/mecro"):
            for f in os.listdir("sample/mecro"):
                file_path = os.path.join("sample/mecro", f)
                if (os.path.isfile(file_path) and
                        os.path.splitext(f)[1].lower() in self.supported_extensions):
                    malware_count += 1

        # 정상 샘플 카운트 (지원 형식만)
        if os.path.exists("sample/clear"):
            for f in os.listdir("sample/clear"):
                file_path = os.path.join("sample/clear", f)
                if (os.path.isfile(file_path) and
                        os.path.splitext(f)[1].lower() in self.supported_extensions):
                    clean_count += 1

        return {
            "malware_samples": malware_count,
            "clean_samples": clean_count,
            "total_samples": malware_count + clean_count,
            "sufficient_data": malware_count >= 10 and clean_count >= 10,
            "supported_formats": list(self.supported_extensions)
        }

    def batch_predict(self, file_paths: list) -> Dict[str, Dict]:
        """다중 파일 예측 (지원 형식만)"""
        if not self.model_loaded:
            if not self.load_model():
                return {"error": "모델을 로드할 수 없습니다"}

        results = {}
        supported_files = []
        unsupported_files = []

        # 파일 형식 필터링
        for file_path in file_paths:
            ext = os.path.splitext(file_path)[1].lower()
            if ext in self.supported_extensions:
                supported_files.append(file_path)
            else:
                unsupported_files.append(file_path)

        # 지원되는 파일 예측
        for file_path in supported_files:
            try:
                file_name = os.path.basename(file_path)
                prediction = self.predict_file(file_path)
                results[file_name] = prediction
            except Exception as e:
                results[os.path.basename(file_path)] = {
                    "error": f"예측 실패: {str(e)}"
                }

        # 지원되지 않는 파일 기록
        for file_path in unsupported_files:
            file_name = os.path.basename(file_path)
            ext = os.path.splitext(file_path)[1].lower()
            results[file_name] = {
                "error": f"지원되지 않는 파일 형식: {ext}",
                "supported_formats": list(self.supported_extensions)
            }

        return results

    def get_model_performance_summary(self) -> Dict[str, Any]:
        """모델 성능 요약 정보"""
        if not self.model_loaded:
            if not self.load_model():
                return {"error": "모델을 로드할 수 없습니다"}

        try:
            # 현재 데이터로 빠른 성능 테스트
            features, labels = self.trainer.prepare_training_data()
            if features is None:
                return {"error": "성능 테스트용 데이터가 없습니다"}

            # 정규화
            features_scaled = self.trainer.scaler.transform(features)

            # 예측
            predictions = self.trainer.ensemble_model.predict(features_scaled)
            probabilities = self.trainer.ensemble_model.predict_proba(features_scaled)

            # 정확도 계산
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

            accuracy = accuracy_score(labels, predictions)
            precision = precision_score(labels, predictions, average='weighted', zero_division=0)
            recall = recall_score(labels, predictions, average='weighted', zero_division=0)
            f1 = f1_score(labels, predictions, average='weighted', zero_division=0)

            return {
                "accuracy": round(accuracy, 4),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "test_samples": len(features),
                "malware_detected": int(sum(predictions)),
                "clean_detected": int(len(predictions) - sum(predictions))
            }

        except Exception as e:
            return {"error": f"성능 평가 중 오류: {str(e)}"}

    def clean_old_models(self, keep_backup=True):
        """이전 모델 파일들 정리"""
        try:
            model_dir = "models"
            if not os.path.exists(model_dir):
                return

            # 백업 생성 (옵션)
            if keep_backup and self.is_model_available():
                import shutil
                import time

                timestamp = int(time.time())
                backup_dir = f"models/backup_{timestamp}"
                os.makedirs(backup_dir, exist_ok=True)

                if os.path.exists(self.trainer.model_path):
                    shutil.copy2(self.trainer.model_path,
                                 os.path.join(backup_dir, "ensemble_model.pkl"))
                if os.path.exists(self.trainer.scaler_path):
                    shutil.copy2(self.trainer.scaler_path,
                                 os.path.join(backup_dir, "scaler.pkl"))
                if os.path.exists(self.trainer.training_history_path):
                    shutil.copy2(self.trainer.training_history_path,
                                 os.path.join(backup_dir, "training_history.pkl"))

                print(f"✅ 모델 백업 생성: {backup_dir}")

            # 임시 파일들 정리
            temp_files = [f for f in os.listdir(model_dir)
                          if f.endswith('.tmp') or f.startswith('temp_')]

            for temp_file in temp_files:
                temp_path = os.path.join(model_dir, temp_file)
                if os.path.isfile(temp_path):
                    os.remove(temp_path)
                    print(f"✅ 임시 파일 삭제: {temp_file}")

        except Exception as e:
            print(f"❌ 모델 정리 중 오류: {e}")

    def get_supported_formats_info(self) -> Dict[str, Any]:
        """지원 파일 형식 정보"""
        format_info = {
            '.hwp': '한글 문서 (Hancom Office)',
            '.hwpx': '한글 문서 XML (Hancom Office)',
            '.docx': 'Microsoft Word 문서',
            '.docm': 'Microsoft Word 매크로 문서',
            '.pdf': 'Adobe PDF 문서',
            '.pptx': 'Microsoft PowerPoint 프레젠테이션',
            '.pptm': 'Microsoft PowerPoint 매크로 프레젠테이션',
            '.xlsx': 'Microsoft Excel 스프레드시트',
            '.xlsm': 'Microsoft Excel 매크로 스프레드시트'
        }

        return {
            "supported_extensions": list(self.supported_extensions),
            "format_descriptions": format_info,
            "total_supported": len(self.supported_extensions)
        }


# 전역 모델 매니저 인스턴스
model_manager = ModelManager()


def get_model_manager() -> ModelManager:
    """모델 매니저 인스턴스 반환"""
    return model_manager


if __name__ == "__main__":
    # 테스트
    manager = ModelManager()

    print("=== 모델 관리자 테스트 ===")

    # 지원 형식 정보
    format_info = manager.get_supported_formats_info()
    print(f"지원 형식: {format_info['total_supported']}개")
    for ext, desc in format_info['format_descriptions'].items():
        print(f"  {ext}: {desc}")

    # 모델 정보 확인
    info = manager.get_model_info()
    print(f"\n모델 정보: {info}")

    # 훈련 데이터 상태 확인
    data_status = manager.get_training_data_status()
    print(f"\n훈련 데이터 상태: {data_status}")

    # 모델이 있으면 테스트 예측
    if manager.is_model_available():
        print("\n모델 로드 테스트...")
        if manager.load_model():
            print("✅ 모델 로드 성공")

            # 성능 요약
            performance = manager.get_model_performance_summary()
            print(f"\n모델 성능: {performance}")

            # 샘플 파일로 예측 테스트
            test_files = []

            # 악성 샘플 테스트
            if os.path.exists("sample/mecro"):
                malware_files = [
                    os.path.join("sample/mecro", f)
                    for f in os.listdir("sample/mecro")[:2]
                    if os.path.isfile(os.path.join("sample/mecro", f))
                ]
                test_files.extend(malware_files)

            # 정상 샘플 테스트
            if os.path.exists("sample/clear"):
                clean_files = [
                    os.path.join("sample/clear", f)
                    for f in os.listdir("sample/clear")[:2]
                    if os.path.isfile(os.path.join("sample/clear", f))
                ]
                test_files.extend(clean_files)

            if test_files:
                print(f"\n{len(test_files)}개 파일 배치 예측 테스트...")
                results = manager.batch_predict(test_files)
                for filename, result in results.items():
                    if "error" in result:
                        print(f"❌ {filename}: {result['error']}")
                    else:
                        print(f"✅ {filename}: {result.get('prediction', 'Unknown')} "
                              f"(신뢰도: {result.get('confidence', 0):.3f})")
        else:
            print("❌ 모델 로드 실패")
    else:
        print("❌ 훈련된 모델이 없습니다")
        print("먼저 다음 명령어로 모델을 훈련하세요:")
        print("python utils/model_trainer.py")