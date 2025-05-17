# 실행 명령어
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
 - 메인 실행 파일

2. macro_remover.py
 - 

3. pdf_with_js.py
 - JavaScript 악성코드 샘플 파일 생성 (실행방법: python pdf_with_js.py)
