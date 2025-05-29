# 앙상블 ML 모델
# 머신러닝 기반 훈련 기능

import pickle
import pandas as pd
import numpy as np
import os
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from .feature_extractor import FeatureExtractor


class EnsembleModelTrainer:
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.scaler = StandardScaler()

        # 다중 모델 앙상블 구성
        self.rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )

        self.svm_model = SVC(
            probability=True,
            random_state=42,
            class_weight='balanced',
            kernel='rbf'
        )

        self.mlp_model = MLPClassifier(
            hidden_layer_sizes=(100, 50, 25),
            random_state=42,
            max_iter=500,
            early_stopping=True
        )

        # 투표 기반 앙상블
        self.ensemble_model = VotingClassifier(
            estimators=[
                ('rf', self.rf_model),
                ('svm', self.svm_model),
                ('mlp', self.mlp_model)
            ],
            voting='soft'  # 확률 기반 투표
        )

    def prepare_training_data(self, malware_files, clean_files):
        """훈련 데이터 준비 (악성 + 정상 파일)"""
        features_list = []
        labels = []

        print(f"악성 파일 처리 중: {len(malware_files)}개")
        # 악성 파일 처리
        for file_path in malware_files:
            try:
                features = self._extract_features(file_path)
                if features:
                    features_list.append(features)
                    labels.append(1)  # 악성
            except Exception as e:
                print(f"악성 파일 처리 오류: {file_path}, {e}")

        print(f"정상 파일 처리 중: {len(clean_files)}개")
        # 정상 파일 처리
        for file_path in clean_files:
            try:
                features = self._extract_features(file_path)
                if features:
                    features_list.append(features)
                    labels.append(0)  # 정상
            except Exception as e:
                print(f"정상 파일 처리 오류: {file_path}, {e}")

        print(f"총 {len(features_list)}개 샘플 처리 완료")
        return pd.DataFrame(features_list), labels

    def _extract_features(self, file_path):
        """파일 타입에 따른 특성 추출"""
        ext = os.path.splitext(file_path)[1].lower()

        if ext in ['.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm']:
            return self.feature_extractor.extract_office_features(file_path)
        elif ext == '.pdf':
            return self.feature_extractor.extract_pdf_features(file_path)
        else:
            return None

    def train_ensemble_model(self, X, y):
        """앙상블 모델 훈련"""
        if len(X) == 0:
            raise ValueError("훈련 데이터가 없습니다")

        # 데이터 전처리
        X_scaled = self.scaler.fit_transform(X)

        # 데이터 분할
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )

        print("앙상블 모델 훈련 시작...")

        # 앙상블 모델 훈련
        self.ensemble_model.fit(X_train, y_train)

        # 성능 평가
        y_pred = self.ensemble_model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred)

        # 교차 검증
        cv_scores = cross_val_score(self.ensemble_model, X_scaled, y, cv=5)

        print(f"테스트 정확도: {accuracy:.4f}")
        print(f"교차 검증 평균: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")

        return accuracy, report, cv_scores

    def save_model(self, model_path):
        """앙상블 모델과 스케일러 저장"""
        model_data = {
            'ensemble_model': self.ensemble_model,
            'scaler': self.scaler
        }
        with open(model_path, 'wb') as f:
            pickle.dump(model_data, f)


class EnsembleModelManager:
    def __init__(self, model_path="models/ensemble_malware_detector.pkl"):
        self.model_path = model_path
        self.ensemble_model = None
        self.scaler = None
        self.feature_extractor = FeatureExtractor()
        self.load_model()

    def load_model(self):
        """저장된 앙상블 모델 로드"""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    model_data = pickle.load(f)
                    self.ensemble_model = model_data['ensemble_model']
                    self.scaler = model_data['scaler']
                return True
            except Exception as e:
                print(f"모델 로드 실패: {e}")
                return False
        return False

    def predict_file(self, file_path):
        """파일의 악성코드 여부 예측"""
        if not self.ensemble_model or not self.scaler:
            return None, "모델이 로드되지 않음", None

        try:
            ext = os.path.splitext(file_path)[1].lower()

            if ext in ['.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm']:
                features = self.feature_extractor.extract_office_features(file_path)
            elif ext == '.pdf':
                features = self.feature_extractor.extract_pdf_features(file_path)
            else:
                return None, "지원되지 않는 파일 형식", None

            # 특성 정규화
            feature_df = pd.DataFrame([features])
            feature_scaled = self.scaler.transform(feature_df)

            # 앙상블 예측
            prediction = self.ensemble_model.predict(feature_scaled)[0]
            probability = self.ensemble_model.predict_proba(feature_scaled)[0]
            confidence = max(probability) * 100

            # 개별 모델 예측 결과
            individual_predictions = {}
            for name, estimator in self.ensemble_model.named_estimators_.items():
                pred = estimator.predict(feature_scaled)[0]
                prob = estimator.predict_proba(feature_scaled)[0]
                individual_predictions[name] = {
                    'prediction': pred,
                    'confidence': max(prob) * 100
                }

            return prediction, f"앙상블 신뢰도: {confidence:.1f}%", individual_predictions

        except Exception as e:
            return None, f"예측 오류: {str(e)}", None
