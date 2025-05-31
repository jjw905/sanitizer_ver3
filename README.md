# 문서형 악성코드 무해화 시스템 v2.0 🛡️

AI 기반 문서 악성코드 탐지 및 무해화 시스템

## 🚀 빠른 시작

### 1. 환경 설정
```bash
# 의존성 설치
pip install -r requirements.txt

# API 키 설정
cp .env.example .env
# .env 파일을 열어서 실제 API 키로 교체
```

### 2. API 키 발급
- **MalwareBazaar**: https://bazaar.abuse.ch/api/
- **VirusTotal**: https://www.virustotal.com/gui/my-apikey

### 3. 시스템 초기화
```bash
# 자동 설정 (데이터 수집 + 모델 훈련)
python test_api.py setup

# 또는 GUI만 실행 (기본 기능만)
python main.py
```

## 📁 주요 기능

### 🤖 AI 기반 탐지
- 머신러닝 앙상블 모델
- 실시간 악성코드 예측
- 신뢰도 기반 위험도 평가

### 🔍 룰 기반 탐지
- PDF JavaScript 탐지
- Office 매크로 탐지
- HWP 스크립트 탐지

### 🛡️ 무해화 처리
- 악성 요소 자동 제거
- 안전한 문서로 변환
- 처리 내역 상세 로깅

## 📂 파일 구조

```
doc_sanitizer/
├── main.py                 # GUI 메인 애플리케이션
├── test_api.py            # 시스템 테스트 및 설정
├── config.py              # API 설정 관리
├── utils/
│   ├── api_client.py      # MalwareBazaar/VirusTotal API
│   ├── model_trainer.py   # AI 모델 훈련
│   ├── model_manager.py   # 모델 관리
│   ├── feature_extractor.py # 특징 추출
│   ├── pdf_sanitizer.py   # PDF 무해화
│   ├── office_macro.py    # Office 매크로 처리
│   └── hwp_sanitizer.py   # HWP 처리
├── sample/
│   ├── mecro/             # 악성 샘플 (로컬만)
│   └── clear/             # 정상/정리된 파일
└── models/                # 훈련된 AI 모델
```

## 🔧 개발 도구

### 모델 재훈련
```bash
python force_retrain.py
```

### 디버깅
```bash
python debug_env.py        # 환경변수 확인
python test_api.py test    # 빠른 기능 테스트
```

## ⚠️ 보안 주의사항

1. **API 키 보호**: `.env` 파일을 Git에 커밋하지 마세요
2. **악성 샘플**: `sample/mecro/` 폴더는 로컬에만 존재
3. **모델 파일**: 용량이 커서 Git에서 제외됨

## 🤝 Git 워크플로우

### 브랜치 전략
```bash
# 개인 브랜치 생성
git checkout -b dev.your_name

# 작업 후 커밋
git add .
git commit -m "작업 내용"
git push origin dev.your_name
```

### 팀원과 동기화
```bash
# 작업 시작 전
git pull origin dev

# 충돌 해결 후
git merge dev
```

## 📊 지원 파일 형식

- **PDF**: `.pdf`
- **Microsoft Office**: `.docx`, `.docm`, `.xlsx`, `.xlsm`, `.pptx`, `.pptm`
- **한글 문서**: `.hwp`, `.hwpx`, `.hwpml`

## 🏆 주요 특징

- ✅ **AI + 룰 기반** 하이브리드 탐지
- ✅ **실시간 처리** 및 진행률 표시
- ✅ **배치 처리** 다중 파일 동시 처리
- ✅ **상세 로그** 탐지/제거 내역 추적
- ✅ **안전한 무해화** 원본 보존

5/31 악성코드 탐지 프로그램 명령어 추가 

# 파일 정리 가이드

## 🗑️ 삭제 가능한 파일들

### 1. 중복 기능 파일
```bash
rm utils/ensemble_model.py  # model_trainer.py와 중복
```

### 2. 일회성/디버깅 파일
```bash
rm quick_fix.py            # 환경설정 수정용 (일회성)
rm debug_env.py            # 디버깅용 임시 파일
```

### 3. 삭제 명령어 (맥북 터미널)
```bash
# 프로젝트 루트에서 실행
rm quick_fix.py
rm debug_env.py
rm utils/ensemble_model.py
```

## 📁 최종 프로젝트 구조

```
doc_sanitizer/
├── main.py                     # 🔥 메인 GUI (개선됨)
├── config.py                   # API 설정
├── test_api.py                 # 시스템 테스트
├── requirements.txt            # 🔥 의존성 (업데이트됨)
├── README.md                   # 프로젝트 문서
├── .env.example               # API 키 예시
├── .gitignore                 # Git 무시 파일
├── utils/
│   ├── __init__.py
│   ├── api_client.py          # API 통신
│   ├── feature_extractor.py   # 특징 추출
│   ├── model_manager.py       # 모델 관리
│   ├── model_trainer.py       # 모델 훈련
│   ├── malware_classifier.py  # 🔥 악성코드 분류 (신규)
│   ├── pdf_sanitizer.py       # PDF 무해화
│   ├── office_macro.py        # Office 매크로 처리
│   └── hwp_sanitizer.py       # HWP 처리
├── sample/
│   ├── mecro/                 # 악성 샘플
│   └── clear/                 # 정상/정리된 파일
└── models/                    # AI 모델 저장소
```

## 🔥 주요 개선사항

### 1. 로그 시스템 개선
- ✅ 로그가 더 이상 자동으로 초기화되지 않음
- ✅ 모든 작업 내용이 누적되어 기록됨
- ✅ 타임스탬프 자동 추가
- ✅ 수동 로그 초기화 버튼 추가

### 2. 악성코드 유형 분류 추가
- ✅ `malware_classifier.py` 모듈 신규 생성
- ✅ 8가지 주요 악성코드 유형 분류
- ✅ 파일명, 내용, 구조 종합 분석
- ✅ 신뢰도 점수와 함께 결과 제공

### 3. 사용자 경험 개선
- ✅ 파일 이동 시 로그 메시지 추가
- ✅ 모든 작업에 상세한 진행 상황 표시
- ✅ 에러 메시지 개선

## 🧪 테스트 방법

1. **환경 설정**
   ```bash
   pip install -r requirements.txt
   ```

2. **기본 테스트**
   ```bash
   python test_api.py test
   ```

3. **GUI 실행**
   ```bash
   python main.py
   ```

## ⚠️ 주의사항

- 삭제한 파일들은 더 이상 사용되지 않으므로 안전하게 제거 가능
- 기존 `.env` 파일과 `sample/` 폴더 내용은 보존
- 모든 기존 기능은 그대로 유지되면서 개선됨