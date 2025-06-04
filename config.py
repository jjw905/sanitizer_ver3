# config.py - 최종 버전
import os
import os; from dotenv import load_dotenv
load_dotenv()

USE_AWS         = os.getenv("USE_AWS", "false").lower() == "true"
AWS_REGION      = os.getenv("AWS_REGION", "ap-southeast-2")
S3_BUCKET       = os.getenv("S3_BUCKET", "malware-sample-878585013612")

RDS_HOST        = os.getenv("RDS_HOST")
RDS_DB          = os.getenv("RDS_DB")
RDS_USER        = os.getenv("RDS_USER")
RDS_PASSWORD    = os.getenv("RDS_PASSWORD")

# API 키 설정
API_KEYS = {
    'malwarebazaar': os.getenv('MALWARE_BAZAAR_API_KEY'),
    'triage': os.getenv('TRIAGE_API_KEY'),
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
}

# API 엔드포인트 설정
API_ENDPOINTS = {
    'malwarebazaar_api': 'https://mb-api.abuse.ch/api/v1/',
    'triage_api': 'https://api.tria.ge/v0/',
    'triage_samples': 'https://api.tria.ge/v0/samples',
    'triage_search': 'https://api.tria.ge/v0/search'
}

# 샘플 수집 설정 (300개 이상 목표)
SAMPLE_LIMITS = {
    'total_malware_target': 300,
    'total_clean_target': 300,
    'minimum_per_type': 40,
    'pdf_target': 80,
    'word_target': 80,
    'excel_target': 60,
    'powerpoint_target': 50,
    'hwp_target': 50,
    'rtf_target': 30,
}

# 디렉토리 설정
DIRECTORIES = {
    'malware_samples': 'sample/mecro',
    'clean_samples': 'sample/clear',      # 자체생성 클린파일
    'sanitized_output': 'sample/clean',   # 무해화된 파일
    'models': 'models',
    'temp': 'temp'
}

# 악성코드 분류 매핑
MALWARE_CLASSIFICATIONS = {
    'emotet': {
        'family': 'Trojan.Emotet',
        'type': '뱅킹 트로이목마',
        'threat_level': '높음',
        'description': '이메일을 통해 전파되며 금융정보를 탈취하고 추가 악성코드를 다운로드'
    },
    'trickbot': {
        'family': 'Trojan.TrickBot',
        'type': '뱅킹 트로이목마',
        'threat_level': '높음',
        'description': '온라인 뱅킹 자격증명을 훔치고 랜섬웨어 배포에 사용'
    },
    'qakbot': {
        'family': 'Trojan.QakBot',
        'type': '정보 탈취 트로이목마',
        'threat_level': '높음',
        'description': '이메일 자격증명과 금융정보를 탈취하며 네트워크 내 횡적 이동'
    },
    'formbook': {
        'family': 'Trojan.FormBook',
        'type': '정보 수집 트로이목마',
        'threat_level': '중간',
        'description': '키로거 기능으로 사용자 입력을 수집하고 웹브라우저 정보 탈취'
    },
    'agent_tesla': {
        'family': 'Trojan.AgentTesla',
        'type': '원격 접근 트로이목마',
        'threat_level': '중간',
        'description': '키로깅, 스크린샷 캡처, 웹캠 액세스 등 원격 모니터링'
    },
    'lokibot': {
        'family': 'Trojan.LokiBot',
        'type': '정보 탈취 트로이목마',
        'threat_level': '중간',
        'description': 'FTP, 이메일, 웹브라우저 자격증명과 암호화폐 지갑 정보 탈취'
    },
    'macro_malware': {
        'family': 'Trojan.MacroMalware',
        'type': '매크로 악성코드',
        'threat_level': '중간',
        'description': 'Office 문서의 매크로를 통해 실행되는 악성코드'
    },
    'pdf_exploit': {
        'family': 'Exploit.PDF',
        'type': 'PDF 익스플로잇',
        'threat_level': '높음',
        'description': 'PDF 뷰어의 취약점을 악용하여 악성코드를 실행'
    },
    'hwp_malware': {
        'family': 'Trojan.HWP',
        'type': 'HWP 악성코드',
        'threat_level': '중간',
        'description': '한글 문서에 포함된 스크립트를 통해 악성 행위 수행'
    },
    'generic_office': {
        'family': 'Trojan.OfficeDoc',
        'type': 'Office 문서 악성코드',
        'threat_level': '중간',
        'description': 'Office 문서를 통해 전파되는 일반적인 악성코드'
    }
}

# 훈련 데이터 충분성 기준
DATA_SUFFICIENCY = {
    'minimum_total_samples': 600,
    'minimum_malware_samples': 300,
    'minimum_clean_samples': 300,
    'minimum_per_file_type': 40,
    'recommended_training_size': 800
}

# Triage API 설정
TRIAGE_CONFIG = {
    'timeout': 60,
    'max_retries': 3,
    'download_formats': ['pdf', 'docx', 'xlsx', 'pptx', 'hwp', 'rtf'],
    'search_queries': [
        'family:emotet', 'family:trickbot', 'family:qakbot',
        'family:formbook', 'family:agent_tesla', 'family:lokibot',
        'tag:office', 'tag:pdf', 'tag:hwp', 'tag:macro',
        'tag:doc', 'tag:docx', 'tag:xls', 'tag:xlsx',
        'tag:ppt', 'tag:pptx', 'tag:rtf'
    ]
}

# 지원 파일 형식
SUPPORTED_FORMATS = {
    'office': ['.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm'],
    'pdf': ['.pdf'],
    'hwp': ['.hwp', '.hwpx', '.hwpml'],
    'all': ['.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm', '.pdf', '.hwp', '.hwpx', '.hwpml']
}

# 서버 연결 설정
SERVER_HOST = os.getenv("SERVER_HOST", "localhost")
SERVER_PORT = os.getenv("SERVER_PORT", "8000")
SERVER_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"

# 디렉토리 자동 생성
def ensure_directories():
    """필요한 디렉토리들을 자동으로 생성"""
    for dir_path in DIRECTORIES.values():
        os.makedirs(dir_path, exist_ok=True)

# 초기화 시 디렉토리 생성
ensure_directories()