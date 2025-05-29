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

## 📞 문의사항

프로젝트 관련 문의는 GitHub Issues를 이용해주세요.

---
**⚠️ 이 도구는 보안 연구 목적으로만 사용하세요.**