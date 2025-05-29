import os
from dotenv import load_dotenv


def fix_env_file():
    """환경변수 파일 자동 수정"""
    print("=== .env 파일 자동 수정 ===")

    # 기존 .env 파일 읽기
    if not os.path.exists('.env'):
        print("❌ .env 파일이 없습니다")
        return False

    with open('.env', 'r') as f:
        content = f.read()

    print("📄 기존 내용:")
    print(content)

    # 잘못된 키 이름 수정
    updated_content = content.replace('MALWAREBAZAAR_AUTH_KEY', 'MALWARE_BAZAAR_API_KEY')

    # 수정된 내용 저장
    with open('.env', 'w') as f:
        f.write(updated_content)

    print("\n✅ .env 파일 수정 완료")
    print("📄 수정된 내용:")
    print(updated_content)

    # 환경변수 다시 로드
    load_dotenv(override=True)  # 기존 값 덮어쓰기

    # 확인
    malware_key = os.getenv('MALWARE_BAZAAR_API_KEY')
    virus_key = os.getenv('VIRUSTOTAL_API_KEY')

    print(f"\n🔍 수정 후 환경변수 확인:")
    if malware_key:
        masked = malware_key[:6] + '*' * (len(malware_key) - 10) + malware_key[-4:]
        print(f"  ✅ MALWARE_BAZAAR_API_KEY: {masked}")
    else:
        print(f"  ❌ MALWARE_BAZAAR_API_KEY: None")

    if virus_key:
        masked = virus_key[:6] + '*' * (len(virus_key) - 10) + virus_key[-4:]
        print(f"  ✅ VIRUSTOTAL_API_KEY: {masked}")
    else:
        print(f"  ❌ VIRUSTOTAL_API_KEY: None")

    # API 연결 테스트
    print(f"\n🌐 API 연결 재테스트:")

    if malware_key:
        try:
            import requests
            response = requests.post("https://mb-api.abuse.ch/api/v1/",
                                     data={"query": "get_info"}, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result.get("query_status") == "ok":
                    print(f"  ✅ MalwareBazaar API 연결 성공!")
                else:
                    print(f"  ⚠️ MalwareBazaar API 응답: {result}")
            else:
                print(f"  ❌ MalwareBazaar API 오류 (코드: {response.status_code})")
        except Exception as e:
            print(f"  ❌ MalwareBazaar 테스트 실패: {e}")

    if virus_key:
        try:
            import requests
            # VirusTotal은 단순한 GET 요청으로 테스트
            headers = {"x-apikey": virus_key}
            response = requests.get("https://www.virustotal.com/api/v3/users/current",
                                    headers=headers, timeout=10)
            if response.status_code == 200:
                print(f"  ✅ VirusTotal API 연결 성공!")
            else:
                print(f"  ❌ VirusTotal API 오류 (코드: {response.status_code})")
                print(f"     응답: {response.text[:100]}...")
        except Exception as e:
            print(f"  ❌ VirusTotal 테스트 실패: {e}")

    return bool(malware_key and virus_key)


def run_full_setup():
    """전체 시스템 설정 실행"""
    print(f"\n🚀 전체 시스템 설정을 시작하시겠습니까?")
    response = input("계속하려면 'y'를 입력하세요: ").lower()

    if response != 'y':
        print("설정을 취소합니다.")
        return

    try:
        print(f"\n📥 훈련 데이터 수집 중...")
        from utils.api_client import collect_training_data
        malware_files, clean_files = collect_training_data(malware_count=15, clean_count=15)

        print(f"✅ 데이터 수집 완료:")
        print(f"  - 악성 샘플: {len(malware_files)}개")
        print(f"  - 정상 샘플: {len(clean_files)}개")

        print(f"\n🧠 AI 모델 훈련 중...")
        from utils.model_trainer import train_model
        success = train_model()

        if success:
            print(f"✅ 모델 훈련 완료!")
            print(f"\n🎉 전체 시스템 설정 완료!")
            print(f"이제 다음 명령어로 GUI를 실행할 수 있습니다:")
            print(f"python main.py")
        else:
            print(f"❌ 모델 훈련 실패")

    except Exception as e:
        print(f"❌ 설정 중 오류 발생: {e}")
        print(f"\n대안으로 더미 데이터를 사용하세요:")
        print(f"python create_dummy_data.py")


if __name__ == "__main__":
    if fix_env_file():
        run_full_setup()
    else:
        print(f"\n⚠️ API 키 설정에 문제가 있습니다.")
        print(f"수동으로 .env 파일을 확인해주세요.")