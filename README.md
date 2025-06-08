# 문서형 악성코드 무해화 시스템 v2.3

Microsoft Office, PDF, 한글 문서의 악성코드 탐지, 상세 분석 및 정밀 무해화 시스템

## 빠른 시작

```bash
python test_api.py setup
python main.py
```

## 환경 설정

```bash
pip install -r requirements.txt
cp .env.example .env
```
(.env 파일을 열어서 실제 API 키로 교체)

### API 키 발급
- **MalwareBazaar**: https://bazaar.abuse.ch/api/
- **VirusTotal**: https://www.virustotal.com/gui/my-apikey

## 주요 기능

- **AI 기반 탐지**: 머신러닝 모델을 통한 악성코드 예측
- **상세 분석**: 매크로, JavaScript 등 악성 요소의 구체적 내용 추출
- **악성코드 분류**: 탐지된 악성코드의 유형 자동 분류 (Emotet, Trickbot 등)
- **정밀 무해화**: 
  - 정밀 제거: 악성 요소만 제거하여 원본 서식 보존
  - 콘텐츠 재조립: 안전한 텍스트와 이미지만 추출하여 새 문서 생성
- **VirusTotal 검증**: 온라인 바이러스 검사 서비스 연동
- **공용 DB 연동**: 바이러스 샘플 공유 및 재훈련 시스템

## 지원 파일 형식

- **Microsoft Office**: .docx, .docm, .xlsx, .xlsm, .pptx, .pptm
- **PDF**: .pdf  
- **한글**: .hwp, .hwpx, .hwpml

## 폴더 구조

```
doc_sanitizer/
├── main.py                 # GUI 메인 애플리케이션
├── test_api.py            # 시스템 테스트 및 설정
├── config.py              # API 설정 관리
├── utils/                 # 핵심 모듈
│   ├── office_reconstructor.py  # Office 문서 재조립
│   └── pdf_reconstructor.py     # PDF 문서 재조립
├── sample/
│   ├── mecro/             # 악성 샘플 (로컬만)
│   ├── clear/             # 자체생성 클린파일
│   └── clean/             # 무해화된 파일
└── models/                # 훈련된 AI 모델
```

## 주요 변경사항 v2.3

1. **상세 분석 기능 추가**: 
   - Office 매크로의 의심 키워드 추출 및 분석
   - PDF JavaScript 내용 추출 및 로깅
   - 악성코드 유형 자동 분류 (MalwareClassifier 통합)
2. **정밀 무해화 옵션 추가**:
   - 정밀 제거: 기존 방식 개선 (더 많은 위험 요소 제거)
   - 콘텐츠 재조립: 안전한 콘텐츠만 추출하여 새 문서 생성
3. **분석 결과 상세 로깅**: 모든 탐지 및 제거 과정을 상세히 기록
4. **무해화 내역 다운로드**: 처리 내역을 텍스트 파일로 저장 가능

## 디버깅

```bash
python force_retrain.py
python debug_env.py
```

## Git 사용법

### 새 브랜치 생성 및 작업

```bash
git checkout -b dev.your_name
git add .
git commit -m "작업 내용"
git push origin dev.your_name
```

### 동기화

```bash
git pull origin dev
```

- sample/mecro/ 폴더는 로컬에만 존재
- 모델 파일은 용량 문제로 Git에서 제외됨

## AWS 연동 설정

### 1. .env 파일 설정
```env
USE_AWS=true
AWS_REGION=ap-southeast-2
S3_BUCKET=your-bucket-name
RDS_HOST=your-rds-endpoint
RDS_DB=your-database-name
RDS_USER=your-username
RDS_PASSWORD=your-password
```

### 2. AWS CLI 설정 (선택사항)

```bash
# AWS CLI 설치 후
aws configure
```

### 3. S3 버킷 업로드

```bash
aws s3 cp models/model_meta.json s3://your-bucket/models/
```

### 4. EC2 원격 접속

```cmd
ssh -i C:\path\to\key.pem -L 8000:localhost:8000 ec2-user@your-ec2-ip
```

### 5. 백엔드 서버 실행
```bash
uvicorn retrain_server:app --host 0.0.0.0 --port 8000
```

## 데이터베이스 스키마

### training_history 테이블
```sql
CREATE TABLE training_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    model_ver VARCHAR(50) NOT NULL,
    sample_count INT NOT NULL,
    accuracy FLOAT NOT NULL,
    trained_at DATETIME NOT NULL
);
```

### virus_samples 테이블  
```sql
CREATE TABLE virus_samples (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    file_hash VARCHAR(64) UNIQUE NOT NULL,
    file_type VARCHAR(50) NOT NULL,
    file_size INT NOT NULL,
    source VARCHAR(100) NOT NULL,
    malware_family VARCHAR(100),
    threat_category VARCHAR(100), 
    is_malicious BOOLEAN NOT NULL,
    s3_key VARCHAR(500),
    uploaded_at DATETIME NOT NULL,
    features_json TEXT
);
```

## 문제 해결

### 관련 이슈
- **7zip 설치**: https://www.7-zip.org/download.html
- **권한 문제**: 관리자 권한으로 실행

### 공통 이슈
- **API 키 오류**: .env 파일에서 키 값 확인
- **모델 로드 실패**: AWS 설정 또는 로컬 파일 확인
- **DB 연결 실패**: RDS 설정 및 보안그룹 확인

## 무해화 방법 설명

### 정밀 제거 (Surgical Removal)
- 악성으로 판단되는 특정 부분만 정확히 제거
- 원본 문서의 레이아웃과 서식을 최대한 보존
- 빠른 처리 속도

### 콘텐츠 재조립 (Content Reconstruction)
- 원본에서 안전한 텍스트와 이미지만 추출
- 깨끗한 새 문서로 재생성
- 모든 잠재적 위협을 원천 차단
- 일부 복잡한 서식은 단순화될 수 있음