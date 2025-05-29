import os
from dotenv import load_dotenv


def debug_env_variables():
    """환경변수 디버깅"""
    print("=== 환경변수 디버깅 ===")

    # 현재 작업 디렉토리 확인
    print(f"현재 작업 디렉토리: {os.getcwd()}")

    # .env 파일 존재 확인
    env_file_path = ".env"
    if os.path.exists(env_file_path):
        print(f"✅ .env 파일 발견: {os.path.abspath(env_file_path)}")

        # .env 파일 내용 읽기 (보안상 일부만 표시)
        with open(env_file_path, 'r') as f:
            content = f.read()
            print(f"📄 .env 파일 내용:")
            for line in content.split('\n'):
                if line.strip() and not line.startswith('#'):
                    key, _, value = line.partition('=')
                    if value:
                        # API 키 일부만 표시 (보안)
                        masked_value = value[:6] + '*' * (len(value) - 10) + value[-4:] if len(
                            value) > 10 else '*' * len(value)
                        print(f"  {key}={masked_value}")
                    else:
                        print(f"  {key}= (값이 비어있음)")
    else:
        print(f"❌ .env 파일이 없습니다: {os.path.abspath(env_file_path)}")
        return False

    # dotenv 로드
    print(f"\n🔄 dotenv 로드 시도...")
    load_result = load_dotenv()
    print(f"dotenv 로드 결과: {load_result}")

    # 환경변수 확인
    print(f"\n🔍 환경변수 확인:")

    malware_key = os.getenv('MALWARE_BAZAAR_API_KEY')
    virus_key = os.getenv('VIRUSTOTAL_API_KEY')

    if malware_key:
        masked_malware = malware_key[:6] + '*' * (len(malware_key) - 10) + malware_key[-4:] if len(
            malware_key) > 10 else '*' * len(malware_key)
        print(f"  MALWARE_BAZAAR_API_KEY: {masked_malware} (길이: {len(malware_key)})")
    else:
        print(f"  MALWARE_BAZAAR_API_KEY: None")

    if virus_key:
        masked_virus = virus_key[:6] + '*' * (len(virus_key) - 10) + virus_key[-4:] if len(
            virus_key) > 10 else '*' * len(virus_key)
        print(f"  VIRUSTOTAL_API_KEY: {masked_virus} (길이: {len(virus_key)})")
    else:
        print(f"  VIRUSTOTAL_API_KEY: None")

    # API 연결 테스트
    print(f"\n🌐 API 연결 테스트:")

    if malware_key:
        try:
            import requests
            response = requests.post("https://mb-api.abuse.ch/api/v1/",
                                     data={"query": "get_info"}, timeout=10)
            if response.status_code == 200:
                print(f"  ✅ MalwareBazaar API 연결 성공")
            else:
                print(f"  ❌ MalwareBazaar API 연결 실패 (상태코드: {response.status_code})")
        except Exception as e:
            print(f"  ❌ MalwareBazaar API 테스트 오류: {e}")
    else:
        print(f"  ⚠️ MalwareBazaar API 키가 없어 테스트 불가")

    if virus_key:
        try:
            import requests
            headers = {"x-apikey": virus_key}
            response = requests.get("https://www.virustotal.com/api/v3/files",
                                    headers=headers, timeout=10)
            if response.status_code in [200, 404]:
                print(f"  ✅ VirusTotal API 연결 성공")
            else:
                print(f"  ❌ VirusTotal API 연결 실패 (상태코드: {response.status_code})")
        except Exception as e:
            print(f"  ❌ VirusTotal API 테스트 오류: {e}")
    else:
        print(f"  ⚠️ VirusTotal API 키가 없어 테스트 불가")

    print(f"\n=== 디버깅 완료 ===")
    return bool(malware_key and virus_key)


if __name__ == "__main__":
    debug_env_variables()