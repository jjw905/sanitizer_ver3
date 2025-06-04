#!/usr/bin/env python3
# setup_env.py - 환경 설정 및 검증 스크립트 v2.2

import os
import sys
from dotenv import load_dotenv


def create_env_file():
    """새로운 .env 파일 생성 또는 기존 파일 업데이트"""
    print("🔧 .env 파일 설정")
    print("=" * 50)

    # 기존 .env 파일 확인
    env_exists = os.path.exists('.env')
    if env_exists:
        print("기존 .env 파일이 발견되었습니다.")

        # 기존 파일 읽기
        with open('.env', 'r', encoding='utf-8') as f:
            existing_content = f.read()

        # 누락된 키 확인
        missing_keys = []
        required_keys = [
            'MALWARE_BAZAAR_API_KEY',
            'VIRUSTOTAL_API_KEY',
            'TRIAGE_API_KEY',
            'USE_AWS',
            'AWS_REGION',
            'S3_BUCKET'
        ]

        for key in required_keys:
            if key not in existing_content:
                missing_keys.append(key)

        if missing_keys:
            print(f"누락된 설정: {', '.join(missing_keys)}")

            # 누락된 키 추가
            with open('.env', 'a', encoding='utf-8') as f:
                f.write('\n# 추가된 설정들\n')
                for key in missing_keys:
                    if key == 'USE_AWS':
                        f.write(f'{key}=false\n')
                    elif key == 'AWS_REGION':
                        f.write(f'{key}=ap-southeast-2\n')
                    elif key == 'S3_BUCKET':
                        f.write(f'{key}=your-bucket-name\n')
                    else:
                        f.write(f'{key}=your_{key.lower()}_here\n')

            print("누락된 설정이 .env 파일에 추가되었습니다.")
        else:
            print("모든 필수 설정이 완료되어 있습니다.")
    else:
        print(".env 파일이 없습니다. 새로 생성합니다...")

        # 새 .env 파일 생성
        env_content = """# 문서형 악성코드 무해화 시스템 v2.2 - 설정파일
# 아래 설정들을 실제 값으로 교체하세요

# API 키 설정 (필수)
MALWARE_BAZAAR_API_KEY=your_malware_bazaar_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
TRIAGE_API_KEY=your_triage_api_key_here

# AWS 설정 (선택사항)
USE_AWS=false
AWS_REGION=ap-southeast-2
S3_BUCKET=your-bucket-name

# RDS 데이터베이스 설정 (선택사항)
RDS_HOST=your-rds-endpoint
RDS_DB=your-database-name
RDS_USER=your-username
RDS_PASSWORD=your-password

# 서버 설정 (선택사항)
SERVER_HOST=localhost
SERVER_PORT=8000
"""

        with open('.env', 'w', encoding='utf-8') as f:
            f.write(env_content)

        print("새 .env 파일이 생성되었습니다.")

    print("\n📋 다음 단계:")
    print("1. .env 파일을 열어서 실제 설정값으로 교체하세요")
    print("2. MalwareBazaar: https://bazaar.abuse.ch/api/")
    print("3. VirusTotal: https://www.virustotal.com/gui/my-apikey")
    print("4. AWS 사용시 USE_AWS=true로 변경")


def create_directories():
    """필요한 디렉토리들 생성"""
    print("\n📁 디렉토리 구조 생성")
    print("=" * 50)

    directories = [
        'sample/mecro',     # 악성 샘플
        'sample/clear',     # 자체생성 클린파일
        'sample/clean',     # 무해화된 파일
        'models',           # AI 모델
        'temp',             # 임시 파일
        'temp_db_samples'   # DB 샘플 임시 저장
    ]

    created_count = 0
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            print(f"생성됨: {directory}/")
            created_count += 1
        else:
            print(f"존재함: {directory}/")

    print(f"\n{created_count}개 디렉토리가 생성되었습니다.")


def check_api_keys():
    """API 키 설정 확인"""
    print("\n🔑 API 키 설정 확인")
    print("=" * 50)

    load_dotenv()

    # 각 API 키 확인
    keys_status = {}

    # MalwareBazaar
    mb_key = os.getenv('MALWARE_BAZAAR_API_KEY')
    if mb_key and mb_key != 'your_malware_bazaar_api_key_here':
        keys_status['MalwareBazaar'] = '설정됨'
    else:
        keys_status['MalwareBazaar'] = '미설정'

    # VirusTotal
    vt_key = os.getenv('VIRUSTOTAL_API_KEY')
    if vt_key and vt_key != 'your_virustotal_api_key_here':
        keys_status['VirusTotal'] = '설정됨'
    else:
        keys_status['VirusTotal'] = '미설정'

    # Tria.ge (선택사항)
    triage_key = os.getenv('TRIAGE_API_KEY')
    if triage_key and triage_key != 'your_triage_api_key_here':
        keys_status['Tria.ge'] = '설정됨 (선택사항)'
    else:
        keys_status['Tria.ge'] = '미설정 (선택사항)'

    # AWS 설정
    use_aws = os.getenv('USE_AWS', 'false').lower() == 'true'
    if use_aws:
        aws_region = os.getenv('AWS_REGION')
        s3_bucket = os.getenv('S3_BUCKET')
        if aws_region and s3_bucket and s3_bucket != 'your-bucket-name':
            keys_status['AWS'] = '설정됨'
        else:
            keys_status['AWS'] = '부분 설정'
    else:
        keys_status['AWS'] = '비활성화'

    # 결과 출력
    for service, status in keys_status.items():
        print(f"  {service}: {status}")

    # 필수 키 확인
    required_set = mb_key and mb_key != 'your_malware_bazaar_api_key_here' and \
                   vt_key and vt_key != 'your_virustotal_api_key_here'

    if required_set:
        print("\n필수 API 키가 모두 설정되었습니다!")
        return True
    else:
        print("\n필수 API 키가 설정되지 않았습니다.")
        print("   .env 파일을 열어서 실제 API 키로 교체해주세요.")
        return False


def test_api_connections():
    """API 연결 테스트"""
    print("\n🌐 API 연결 테스트")
    print("=" * 50)

    try:
        from utils.api_client import APIClient

        client = APIClient()

        # MalwareBazaar 테스트
        print("📋 MalwareBazaar 테스트 중...")
        mb_result = client.test_malware_bazaar_connection()
        print(f"  결과: {'연결 성공' if mb_result else '연결 실패'}")

        # VirusTotal 테스트
        print("\n🦠 VirusTotal 테스트 중...")
        vt_result = client.test_virustotal_connection()
        print(f"  결과: {'연결 성공' if vt_result else '연결 실패'}")

        return mb_result and vt_result

    except ImportError as e:
        print(f"모듈 임포트 실패: {e}")
        print("   필요한 패키지를 설치하세요: pip install -r requirements.txt")
        return False
    except Exception as e:
        print(f"연결 테스트 실패: {e}")
        return False


def install_dependencies():
    """필요한 패키지 설치"""
    print("\n📦 의존성 패키지 설치")
    print("=" * 50)

    try:
        import subprocess

        # requirements.txt에서 패키지 설치
        if os.path.exists('requirements.txt'):
            print("requirements.txt에서 패키지 설치 중...")
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
            ], capture_output=True, text=True)

            if result.returncode == 0:
                print("모든 패키지 설치 완료")
                return True
            else:
                print(f"패키지 설치 실패: {result.stderr}")
                return False
        else:
            print("requirements.txt 파일이 없습니다")
            return False

    except Exception as e:
        print(f"설치 중 오류: {e}")
        return False


def check_7zip():
    """7zip 설치 확인"""
    print("\n🗜️ 압축 해제 도구 확인")
    print("=" * 50)

    try:
        import subprocess

        # 7zip 확인
        result = subprocess.run(['7z'], capture_output=True, timeout=5)
        print("7zip 설치됨")
        return True

    except FileNotFoundError:
        print("7zip이 설치되지 않았습니다")
        print("   macOS 설치: brew install p7zip")
        print("   Windows 설치: https://www.7-zip.org/download.html")
        return False
    except Exception as e:
        print(f"7zip 확인 중 오류: {e}")
        return False


def check_aws_config():
    """AWS 설정 확인"""
    print("\n☁️ AWS 설정 확인")
    print("=" * 50)

    load_dotenv()
    use_aws = os.getenv('USE_AWS', 'false').lower() == 'true'

    if not use_aws:
        print("AWS 사용 안함 (USE_AWS=false)")
        return True

    # AWS 관련 환경변수 확인
    aws_region = os.getenv('AWS_REGION')
    s3_bucket = os.getenv('S3_BUCKET')
    rds_host = os.getenv('RDS_HOST')

    print(f"AWS Region: {aws_region or '미설정'}")
    print(f"S3 Bucket: {s3_bucket or '미설정'}")
    print(f"RDS Host: {rds_host or '미설정 (선택사항)'}")

    # boto3 설치 확인
    try:
        import boto3
        print("boto3 라이브러리: 설치됨")

        # AWS 자격증명 확인
        try:
            session = boto3.Session()
            credentials = session.get_credentials()
            if credentials:
                print("AWS 자격증명: 설정됨")
                return True
            else:
                print("AWS 자격증명: 미설정")
                print("   aws configure 실행 또는 IAM 역할 설정 필요")
                return False
        except Exception as cred_error:
            print(f"AWS 자격증명 확인 실패: {cred_error}")
            return False

    except ImportError:
        print("boto3 라이브러리: 미설치")
        print("   설치 명령어: pip install boto3")
        return False


def main():
    """메인 설정 프로세스"""
    print("🚀 문서형 악성코드 무해화 시스템 v2.2 - 환경 설정")
    print("=" * 60)

    # 1. 디렉토리 생성
    create_directories()

    # 2. .env 파일 생성/확인
    create_env_file()

    # 3. 의존성 설치
    deps_ok = install_dependencies()

    # 4. 7zip 확인
    zip_ok = check_7zip()

    # 5. API 키 확인
    keys_ok = check_api_keys()

    # 6. AWS 설정 확인
    aws_ok = check_aws_config()

    # 7. API 연결 테스트 (키가 설정된 경우만)
    if keys_ok:
        connections_ok = test_api_connections()
    else:
        connections_ok = False

    # 최종 결과
    print("\n" + "=" * 60)
    print("📊 설정 완료 상태")
    print("=" * 60)
    print(f"📁 디렉토리 구조: 완료")
    print(f"📦 의존성 패키지: {'완료' if deps_ok else '실패'}")
    print(f"🗜️ 압축 해제 도구: {'완료' if zip_ok else '선택사항'}")
    print(f"🔑 API 키 설정: {'완료' if keys_ok else '필요'}")
    print(f"☁️ AWS 설정: {'완료' if aws_ok else '선택사항'}")
    print(f"🌐 API 연결: {'완료' if connections_ok else '확인 필요'}")

    if all([deps_ok, keys_ok, connections_ok]):
        print("\n모든 설정이 완료되었습니다!")
        print("다음 명령어로 시스템을 시작할 수 있습니다:")
        print("  python test_api.py setup    # 데이터 수집 및 모델 훈련")
        print("  python main.py              # GUI 실행")
    else:
        print("\n일부 설정이 완료되지 않았습니다.")
        print("위의 오류들을 해결한 후 다시 실행해주세요.")

        if not keys_ok:
            print("\n🔧 API 키 설정 방법:")
            print("1. .env 파일을 텍스트 에디터로 열기")
            print("2. 'your_api_key_here' 부분을 실제 발급받은 키로 교체")
            print("3. 파일 저장 후 다시 실행")


if __name__ == "__main__":
    main()