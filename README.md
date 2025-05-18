# 실행 명령어
 - 모듈 설치(최초 1회 실행)
```sh
pip install -r requirements.txt
```
 - 프로그램 실행 명령어
```sh
python main.py
```

# 작동 순서
1. 문서 업로드
  - 사용자가 .pdf, .docx, .docm 선택

2. 문서 구조 분석
  - PDF 구조 내 /JavaScript, /OpenAction 등 악성 키 탐색

3. 무해화 처리 (PDF)
  - PyPDF2로 문서 구조 읽고 위험 키 삭제 → 재저장

4. 무해화 처리 (DOCX)
  - zip 구조의 vbaProject.bin 존재 여부 확인 → 삭제 후 재압축

5. 로그 출력 + 히스토리 기록
  - 처리 결과를 시각화 → 어떤 키가 제거되었는지 기록

6. 무해화 결과 파일 저장
  - *_clean.pdf 또는 *_clean.docx 로 저장

# 파일 구조
1. main.py
  - 문서 무해화 GUI 애플리케이션의 진입점

2. utils/office_macro.py
  - Office 문서(Word, Excel, PPT)의 매크로 제거 및 탐지

3. utils/pdf_sanitizer.py
  - PDF 문서 내 악성 JavaScript 탐지 및 제거

4. utils/hwp_sanitizer.py
  - .hwp, .hwpx, .hwpml 문서 내 위험 문자열 제거

5. 기타 파일
  - sample/mecro - mecro 악성코드 샘플
  - sample/clear - 무해화 된 파일 저장 폴더
  - requirements.txt - 의존성 모듈 목록

# 필수 설치 파일
  - python 3.11.x 이상
  - git
  - sourcetree
  - visual studio code / cursor ai (둘 중 하나)

# Sourcetree 설치
 1. https://www.sourcetreeapp.com/ 접속 후 Sourcetree 다운로드
 2. installer에서 첫 화면(비트버킷 로그인) 건너뛰기
 3. Mercurial 선택 해제 후 다음
 4. Preferences에서 github 이메일 주소 입력 후 다음
 5. SSH 인증 메시지 출력 시 "아니오" 선택

# 프로젝트 다운로드(클론) 및 git 사용법
 1 프로젝트 다운로드(클론)
  - sourcetree 상단에 clone 버튼 클릭
  - 소스경로(https://github.com/bgeun31/doc_sanitizer), 목적지 경로(탐색 누르고 본인이 원하는 저장할 폴더 선택) 입력
  - 클론(clone) 클릭
  - 저장할 폴더에 정상적으로 프로젝트 파일들이 다운됐는지 확인

 2. git branch 생성 (최초 1회만 진행)
  - 상단에 브랜치 클릭
  - 새 브랜치 항목에 본인이 작업할 공간의 이름을 입력 후 브랜치 생성 클릭 (ex. dev.song)
  - 왼쪽 사이드바에 본인 브랜치에 점이 있는지 확인(현재 브랜치 확인)
  - 이후 다시 클론할 경우 왼쪽 사이드바에 원격-origin-본인 브랜치 순으로 클릭해서 이동하면 됨.

3. git commit, pull, push 사용법
  - 본인이 코드를 수정하거나 작업하면 왼쪽 사이드바 '파일 상태'에 변경된 파일 목록이 뜸.
  - commit할 파일들을 올리고 하단 창에 본인이 작업한 내용을 작성하고 커밋을 하면 됨.
  - 작업하는 동안 commit을 진행하고 작업이 완료되면 상단에 push를 누르고 본인 브랜치만 체크한 후 Push 진행.
  - Github 본인 브랜치에 작업한 내용이 잘 올라갔는지 확인.

  - 작업을 시작하기 전 pull을 통해 팀원들이 작업한 결과물을 불러온 후 작업을 진행해야 함.
  - 상단에 pull 버튼을 눌러서 '가져오기 위한 원격 브랜치' 탭에서 dev 브랜치를 선택하고 pull 진행.
