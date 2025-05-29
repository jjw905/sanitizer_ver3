# config.py - 수정된 버전
import os
from dotenv import load_dotenv

load_dotenv()

API_KEYS = {
    'malwarebazaar': os.getenv('MALWARE_BAZAAR_API_KEY'),  # 수정됨
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
}

API_ENDPOINTS = {
    'malwarebazaar_api': 'https://mb-api.abuse.ch/api/v1/',
    'virustotal_scan': 'https://www.virustotal.com/api/v3/files',  # v3로 업데이트
    'virustotal_report': 'https://www.virustotal.com/api/v3/files'
}

# 샘플 수집 설정
SAMPLE_LIMITS = {
    'malware_per_type': 40,  # 타입당 40개 * 5타입 = 200개
    'clean_per_type': 40,    # 정상 파일도 200개
    'total_limit': 200
}