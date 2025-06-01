문서형 악성코드 무해화 시스템 v2.2
Microsoft Office, PDF, 한글 문서의 악성코드 탐지 및 무해화 시스템

빠른 시작
1. 환경 설정
맥북 (macOS)

bash
pip install -r requirements.txt
cp .env.example .env
# .env 파일을 열어서 실제 API 키로 교체

윈도우 (Windows)
cmd
pip install -r requirements.txt
copy .env.example .env

# .env 파일을 메모장으로 열어서 실제 API 키로 교체
2. API 키 발급
MalwareBazaar: https://bazaar.abuse.ch/api/
VirusTotal: https://www.virustotal.com/gui/my-apikey

3. 시스템 실행
맥북
bash
python test_api.py setup
python main.py

윈도우
cmd
python test_api.py setup
python main.py

주요 기능
AI 기반 탐지: 머신러닝 모델을 통한 악성코드 예측
룰 기반 탐지: Office 매크로, PDF JavaScript, HWP 스크립트 탐지
VirusTotal 검증: 온라인 바이러스 검사 서비스 연동
문서 무해화: 악성 요소 제거 및 안전한 문서 생성
지원 파일 형식
Microsoft Office: .docx, .docm, .xlsx, .xlsm, .pptx, .pptm
PDF: .pdf
한글: .hwp, .hwpx, .hwpml

폴더 구조
doc_sanitizer/
├── main.py                 # GUI 메인 애플리케이션
├── test_api.py            # 시스템 테스트 및 설정
├── config.py              # API 설정 관리
├── utils/                 # 핵심 모듈
├── sample/
│   ├── mecro/             # 악성 샘플 (로컬만)
│   └── clear/             # 정상/정리된 파일
└── models/                # 훈련된 AI 모델
개발 도구
모델 재훈련

맥북: python force_retrain.py
윈도우: python force_retrain.py
디버깅

맥북: python debug_env.py
윈도우: python debug_env.py
Git 사용법
개인 브랜치 생성

bash
git checkout -b dev.your_name
git add .
git commit -m "작업 내용"
git push origin dev.your_name
동기화

bash
git pull origin dev

sample/mecro/ 폴더는 로컬에만 존재
모델 파일은 용량 문제로 Git에서 제외됨
