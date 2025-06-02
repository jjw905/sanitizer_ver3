# utils/model_trainer.py - 개선된 버전 (증분 학습 지원)

import os
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.ensemble import VotingClassifier
import pandas as pd
from utils.feature_extractor import FeatureExtractor
from sqlalchemy import text          
from utils import db


class ModelTrainer:
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.scaler = StandardScaler()
        self.ensemble_model = None
        self.model_path = "models/ensemble_model.pkl"
        self.scaler_path = "models/scaler.pkl"
        self.training_history_path = "models/training_history.pkl"

        # 모델 디렉토리 생성
        os.makedirs("models", exist_ok=True)

    def prepare_training_data(self, malware_dir: str = "sample/mecro",
                              clean_dir: str = "sample/clear") -> tuple:
        """훈련 데이터 준비 (지원 형식만)"""
        print("=== 훈련 데이터 준비 중 ===")

        # 지원 확장자 정의
        supported_extensions = {'.hwp', '.hwpx', '.docx', '.docm', '.pdf', '.pptx', '.pptm', '.xlsx', '.xlsm'}

        # 악성 파일 목록 (지원 형식만)
        malware_files = []
        if os.path.exists(malware_dir):
            for f in os.listdir(malware_dir):
                file_path = os.path.join(malware_dir, f)
                if (os.path.isfile(file_path) and
                        os.path.splitext(f)[1].lower() in supported_extensions):
                    malware_files.append(file_path)

        # 정상 파일 목록 (지원 형식만)
        clean_files = []
        if os.path.exists(clean_dir):
            for f in os.listdir(clean_dir):
                file_path = os.path.join(clean_dir, f)
                if (os.path.isfile(file_path) and
                        os.path.splitext(f)[1].lower() in supported_extensions):
                    clean_files.append(file_path)

        print(f"악성 파일: {len(malware_files)}개 (지원 형식만)")
        print(f"정상 파일: {len(clean_files)}개 (지원 형식만)")

        if len(malware_files) < 5 or len(clean_files) < 5:
            print("⚠️  훈련 데이터가 부족합니다. 각각 최소 5개 이상 필요합니다.")
            return None, None

        # 특징 추출
        print("특징 추출 중...")

        all_files = malware_files + clean_files
        features = self.feature_extractor.extract_features_batch(all_files)

        # 라벨 생성 (1: 악성, 0: 정상)
        labels = np.array([1] * len(malware_files) + [0] * len(clean_files))

        print(f"특징 벡터 크기: {features.shape}")
        print(f"라벨 분포 - 악성: {np.sum(labels)}, 정상: {len(labels) - np.sum(labels)}")

        return features, labels

    def save_training_history(
        self,
        features,
        labels,
        accuracy: float,             # ⬅ accuracy 인자 추가
        model_version: str = "1.0"
    ):
        """훈련 기록을 RDS + 로컬 파일에 저장"""
        try:
            history_data = {
                "features": features,
                "labels": labels,
                "model_version": model_version,
                "training_date": pd.Timestamp.now(),
                "sample_count": len(features),
                "accuracy": accuracy
            }

            # ─── 1) RDS INSERT ──────────────────────────
            if db.engine:                            # ← RDS 연결이 있을 때만
                with db.engine.begin() as conn:
                    conn.execute(
                        text(
                            "INSERT INTO training_history "
                            "(model_ver, sample_count, accuracy) "
                            "VALUES (:v, :c, :a)"
                        ),
                        {"v": model_version, "c": len(features), "a": accuracy}
                    )

            # ─── 2) 로컬 history 파일 (증분 학습용) ───────
            with open(self.training_history_path, "wb") as f:
                pickle.dump(history_data, f)

            print(f"✅ 훈련 기록 저장 완료: {len(features)}개 샘플, acc={accuracy:.3f}")

        except Exception as e:
            print(f"❌ 훈련 기록 저장 실패: {e}")

    def load_training_history(self):
        """이전 훈련 기록 로드"""
        try:
            if os.path.exists(self.training_history_path):
                with open(self.training_history_path, 'rb') as f:
                    history_data = pickle.load(f)

                print(f"✅ 이전 훈련 기록 로드: {history_data['sample_count']}개 샘플")
                print(f"   버전: {history_data['model_version']}")
                print(f"   훈련일: {history_data['training_date']}")

                return history_data['features'], history_data['labels']
            else:
                print("이전 훈련 기록이 없습니다.")
                return None, None

        except Exception as e:
            print(f"❌ 훈련 기록 로드 실패: {e}")
            return None, None

    def incremental_train_model(self, test_size=0.2):
        """증분 학습 (기존 데이터 + 새 데이터)"""
        print("=== 모델 증분 학습 시작 ===")

        # 새로운 데이터 준비
        new_features, new_labels = self.prepare_training_data()
        if new_features is None:
            print("❌ 새로운 훈련 데이터 준비 실패")
            return False

        # 이전 훈련 데이터 로드
        old_features, old_labels = self.load_training_history()

        if old_features is not None and old_labels is not None:
            print("기존 데이터와 새 데이터를 결합합니다...")

            # 데이터 결합
            try:
                # 특징 수가 다를 수 있으므로 확인
                if old_features.shape[1] != new_features.shape[1]:
                    print(f"⚠️  특징 수가 다릅니다. 기존: {old_features.shape[1]}, 새로운: {new_features.shape[1]}")
                    print("기존 데이터를 무시하고 새 데이터로만 훈련합니다.")
                    combined_features = new_features
                    combined_labels = new_labels
                else:
                    combined_features = np.vstack([old_features, new_features])
                    combined_labels = np.concatenate([old_labels, new_labels])

                print(f"결합된 데이터: {len(combined_features)}개 샘플")
                print(f"  - 기존: {len(old_features)}개")
                print(f"  - 새로운: {len(new_features)}개")

            except Exception as e:
                print(f"데이터 결합 실패: {e}")
                print("새 데이터로만 훈련합니다.")
                combined_features = new_features
                combined_labels = new_labels
        else:
            print("기존 데이터가 없습니다. 새 데이터로만 훈련합니다.")
            combined_features = new_features
            combined_labels = new_labels

        # 모델 훈련
        success, ensemble_accuracy = self._train_with_data(combined_features, combined_labels, test_size)

        if success:
            # 새로운 훈련 기록 저장
            self.save_training_history(combined_features, combined_labels, "2.0+", ensemble_accuracy, "2.0+")

        return success

    def train_model(self, test_size=0.2):
        """전체 모델 훈련 (처음부터)"""
        print("=== 모델 전체 훈련 시작 ===")

        # 데이터 준비
        features, labels = self.prepare_training_data()
        if features is None:
            print("❌ 훈련 데이터 준비 실패")
            return False

        # 모델 훈련
        success, ensemble_accuracy = self._train_with_data(features, labels, test_size)

        if success:
            # 훈련 기록 저장
            self.save_training_history(features, labels, ensemble_accuracy, "1.0")

        return success

    def _train_with_data(self, features, labels, test_size):
        """실제 모델 훈련 수행"""
        try:
            # 데이터 분할
            X_train, X_test, y_train, y_test = train_test_split(
                features, labels, test_size=test_size, random_state=42,
                stratify=labels if len(np.unique(labels)) > 1 else None
            )

            # 데이터 정규화
            print("데이터 정규화 중...")
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)

            # 개별 모델 훈련
            trained_models, model_scores = self.train_individual_models(
                X_train_scaled, X_test_scaled, y_train, y_test
            )

            # 앙상블 모델 생성 및 훈련
            self.ensemble_model = self.create_ensemble_model(trained_models)
            self.ensemble_model.fit(X_train_scaled, y_train)

            # 앙상블 모델 평가
            print("\n=== 앙상블 모델 평가 ===")
            ensemble_pred = self.ensemble_model.predict(X_test_scaled)
            ensemble_accuracy = accuracy_score(y_test, ensemble_pred)

            print(f"앙상블 정확도: {ensemble_accuracy:.4f}")
            print("앙상블 분류 리포트:")
            print(classification_report(y_test, ensemble_pred, target_names=['정상', '악성']))

            # 혼동 행렬
            cm = confusion_matrix(y_test, ensemble_pred)
            print(f"혼동 행렬:\n{cm}")

            # 모델 저장
            self.save_model()

            print("✅ 모델 훈련 완료!")
            return True, ensemble_accuracy

        except Exception as e:
            print(f"❌ 모델 훈련 실패: {e}")
            return False, None

    def train_individual_models(self, X_train, X_test, y_train, y_test):
        """개별 모델 훈련 및 평가"""
        models = {
            'RandomForest': RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=10,
                min_samples_split=5,
                class_weight='balanced'
            ),
            'GradientBoosting': GradientBoostingClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=6,
                learning_rate=0.1
            ),
            'SVM': SVC(
                kernel='rbf',
                probability=True,
                random_state=42,
                C=1.0,
                gamma='scale',
                class_weight='balanced'
            )
        }

        trained_models = {}
        model_scores = {}

        print("\n=== 개별 모델 훈련 ===")

        for name, model in models.items():
            print(f"\n{name} 훈련 중...")

            # 모델 훈련
            model.fit(X_train, y_train)

            # 예측
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)

            # 교차 검증 (샘플이 적을 경우 cv=3)
            cv_folds = min(3, len(np.unique(y_train)))
            if cv_folds > 1:
                cv_scores = cross_val_score(model, X_train, y_train, cv=cv_folds, scoring='accuracy')
            else:
                cv_scores = np.array([accuracy])

            trained_models[name] = model
            model_scores[name] = {
                'accuracy': accuracy,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std()
            }

            print(f"{name} - 정확도: {accuracy:.4f}")
            print(f"{name} - CV 평균: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

        return trained_models, model_scores

    def create_ensemble_model(self, trained_models):
        """앙상블 모델 생성"""
        print("\n=== 앙상블 모델 생성 ===")

        # 보팅 분류기 생성
        voting_clf = VotingClassifier(
            estimators=[
                ('rf', trained_models['RandomForest']),
                ('gb', trained_models['GradientBoosting']),
                ('svm', trained_models['SVM'])
            ],
            voting='soft'  # 확률 기반 투표
        )

        return voting_clf

    def save_model(self):
        """모델과 스케일러 저장"""
        try:
            # 앙상블 모델 저장
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.ensemble_model, f)

            # 스케일러 저장
            with open(self.scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)

            print(f"✅ 모델 저장 완료: {self.model_path}")
            print(f"✅ 스케일러 저장 완료: {self.scaler_path}")

        except Exception as e:
            print(f"❌ 모델 저장 실패: {e}")

    def load_model(self):
        """저장된 모델과 스케일러 로드"""
        try:
            # 앙상블 모델 로드
            with open(self.model_path, 'rb') as f:
                self.ensemble_model = pickle.load(f)

            # 스케일러 로드
            with open(self.scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)

            print("✅ 모델 로드 완료")
            return True

        except Exception as e:
            print(f"❌ 모델 로드 실패: {e}")
            return False

    def predict(self, file_path: str) -> dict:
        """파일 악성코드 예측"""
        if self.ensemble_model is None:
            if not self.load_model():
                return {"error": "모델을 로드할 수 없습니다"}

        try:
            # 지원 형식 확인
            ext = os.path.splitext(file_path)[1].lower()
            supported_extensions = {'.hwp', '.hwpx', '.docx', '.docm', '.pdf', '.pptx', '.pptm', '.xlsx', '.xlsm'}

            if ext not in supported_extensions:
                return {"error": f"지원되지 않는 파일 형식: {ext}"}

            # 특징 추출
            features = self.feature_extractor.extract_file_features(file_path)

            # 수치형 특징만 추출
            numeric_features = np.array([[
                features['file_size'],
                features['entropy'],
                features['suspicious_keywords_count'],
                int(features['has_macro']),
                features['pdf_js_count'],
                int(features['pdf_openaction']),
                features.get('pdf_pages', 0),
                int(features.get('pdf_encryption', False)),
                features.get('macro_suspicious_count', 0),
                int(features.get('has_external_links', False)),
                features.get('xml_complexity', 0),
                features.get('hwp_scripts', 0),
                features.get('hwp_ole_objects', 0),
                features['string_entropy'],
                features['compression_ratio']
            ]])

            # 정규화
            features_scaled = self.scaler.transform(numeric_features)

            # 예측
            prediction = self.ensemble_model.predict(features_scaled)[0]
            probability = self.ensemble_model.predict_proba(features_scaled)[0]

            return {
                "prediction": "악성" if prediction == 1 else "정상",
                "confidence": max(probability),
                "malware_probability": probability[1] if len(probability) > 1 else 0,
                "clean_probability": probability[0],
                "features": features
            }

        except Exception as e:
            return {"error": f"예측 중 오류: {str(e)}"}

    def evaluate_model(self):
        """모델 성능 평가"""
        if self.ensemble_model is None:
            if not self.load_model():
                print("❌ 모델을 로드할 수 없습니다")
                return

        # 테스트 데이터로 재평가
        features, labels = self.prepare_training_data()
        if features is None:
            print("❌ 평가 데이터가 없습니다")
            return

        # 정규화
        features_scaled = self.scaler.transform(features)

        # 예측
        predictions = self.ensemble_model.predict(features_scaled)
        probabilities = self.ensemble_model.predict_proba(features_scaled)

        # 성능 지표
        accuracy = accuracy_score(labels, predictions)

        print("=== 모델 성능 평가 ===")
        print(f"정확도: {accuracy:.4f}")
        print("\n분류 리포트:")
        print(classification_report(labels, predictions, target_names=['정상', '악성']))
        print(f"\n혼동 행렬:\n{confusion_matrix(labels, predictions)}")

        # 개별 파일 예측 결과 (일부만)
        print("\n=== 샘플 예측 결과 ===")

        # 악성 파일 테스트
        if os.path.exists("sample/mecro"):
            malware_files = [f for f in os.listdir("sample/mecro")
                             if os.path.isfile(os.path.join("sample/mecro", f))][:3]
            for file_name in malware_files:
                file_path = os.path.join("sample/mecro", file_name)
                result = self.predict(file_path)
                print(
                    f"악성 파일 {file_name}: {result.get('prediction', 'Error')} (신뢰도: {result.get('confidence', 0):.3f})")

        # 정상 파일 테스트
        if os.path.exists("sample/clear"):
            clean_files = [f for f in os.listdir("sample/clear")
                           if os.path.isfile(os.path.join("sample/clear", f))][:3]
            for file_name in clean_files:
                file_path = os.path.join("sample/clear", file_name)
                result = self.predict(file_path)
                print(
                    f"정상 파일 {file_name}: {result.get('prediction', 'Error')} (신뢰도: {result.get('confidence', 0):.3f})")


def train_model():
    """모델 훈련 실행 함수"""
    trainer = ModelTrainer()

    # 훈련 데이터 확인
    malware_count = 0
    clean_count = 0

    if os.path.exists("sample/mecro"):
        malware_count = len([f for f in os.listdir("sample/mecro")
                             if os.path.isfile(os.path.join("sample/mecro", f))])

    if os.path.exists("sample/clear"):
        clean_count = len([f for f in os.listdir("sample/clear")
                           if os.path.isfile(os.path.join("sample/clear", f))])

    print(f"현재 데이터: 악성 {malware_count}개, 정상 {clean_count}개")

    if malware_count < 10 or clean_count < 10:
        print("⚠️  훈련 데이터가 부족합니다. 데이터 수집을 시작합니다...")
        try:
            from utils.api_client import collect_training_data
            collect_training_data(malware_count=15, clean_count=15)
        except Exception as e:
            print(f"❌ 데이터 수집 실패: {e}")
            print("수동으로 sample/mecro와 sample/clear 폴더에 파일을 추가해주세요.")
            return False

    # 모델 훈련 (전체 학습)
    success = trainer.train_model()

    if success:
        # 모델 평가
        trainer.evaluate_model()

    return success


def update_model():
    """모델 업데이트 (증분 학습)"""
    trainer = ModelTrainer()

    print("=== 모델 업데이트 (증분 학습) ===")

    # 증분 학습 실행
    success = trainer.incremental_train_model()

    if success:
        print("✅ 모델 업데이트 완료!")
        # 모델 평가
        trainer.evaluate_model()
    else:
        print("❌ 모델 업데이트 실패")

    return success


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "update":
            update_model()
        else:
            train_model()
    else:
        train_model()