# 신규추가 파일
# .env 파일에서 기입한 API 키 호출 기능
import os
from dotenv import load_dotenv

load_dotenv()

API_KEYS = {
    'malwarebazaar': os.getenv('MALWAREBAZAAR_AUTH_KEY'),
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
}

API_ENDPOINTS = {
    'malwarebazaar_api': 'https://mb-api.abuse.ch/api/v1/',
    'virustotal_scan': 'https://www.virustotal.com/vtapi/v2/file/scan',
    'virustotal_report': 'https://www.virustotal.com/vtapi/v2/file/report'
}

# 샘플 수집 설정
SAMPLE_LIMITS = {
    'malware_per_type': 40,  # 타입당 40개 * 5타입 = 200개
    'clean_per_type': 40,    # 정상 파일도 200개
    'total_limit': 200
}
