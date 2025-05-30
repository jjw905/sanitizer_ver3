import os
import sys
from dotenv import load_dotenv
from utils.api_client import APIClient, collect_training_data
from utils.model_manager import ModelManager
from utils.model_trainer import train_model


class ProgressTracker:
    def __init__(self, total_steps):
        self.total_steps = total_steps
        self.current_step = 0

    def update(self, message=""):
        self.current_step += 1
        percentage = (self.current_step / self.total_steps) * 100
        bar_length = 40
        filled_length = int(bar_length * self.current_step // self.total_steps)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)

        sys.stdout.write(f'\r[{bar}] {percentage:.1f}% - {message}')
        sys.stdout.flush()

        if self.current_step == self.total_steps:
            print()  # 새 줄 추가


def test_system():
    """전체 시스템 테스트"""
    print("=== 전체 시스템 테스트 ===")

    # 환경 변수 로드
    load_dotenv()

    # 1. API 연결 테스트
    print("1. API 연결 테스트")
    api_client = APIClient()

    # MalwareBazaar API 테스트
    if api_client.malware_bazaar_key:
        print("  ✔ MalwareBazaar API 키 설정됨")
        if api_client.test_malware_bazaar_connection():
            print("  ✔ MalwareBazaar API 연결 성공")
        else:
            print("  ✗ MalwareBazaar API 연결 실패")
    else:
        print("  ✗ MalwareBazaar API 키 없음")

    # Triage API 테스트 (VirusTotal 대신)
    if api_client.triage_key:
        print("  ✔ Triage API 키 설정됨")
        if api_client.test_triage_connection():
            print("  ✔ Triage API 연결 성공")
        else:
            print("  ✗ Triage API 연결 실패")
    else:
        print("  ✗ Triage API 키 없음 (선택사항)")

    # 2. 모델 및 데이터 상태 확인
    print("\n2. 모델 로드 테스트")
    model_manager = ModelManager()

    if model_manager.is_model_available():
        print("  ✔ 앙상블 모델 존재")
        if model_manager.load_model():
            print("  ✔ 모델 로드 성공")
        else:
            print("  ✗ 모델 로드 실패")
    else:
        print("  ✗ 앙상블 모델 없음 (훈련 필요)")

    # 3. 데이터 폴더 확인
    print("\n3. 데이터 폴더 확인")
    data_status = model_manager.get_training_data_status()

    print(f"  악성 샘플: {data_status['malware_samples']}개")
    print(f"  정상 샘플: {data_status['clean_samples']}개")

    if data_status['sufficient_data']:
        print("  ✔ 충분한 훈련 데이터")
    else:
        print("  ⚠ 훈련 데이터 부족 (악성 300개, 정상 300개 필요)")

    # 4. 모델 정보 출력
    model_info = model_manager.get_model_info()
    if model_info['model_available']:
        print(f"\n4. 모델 정보")
        print(f"  모델 크기: {model_info.get('model_size_mb', 0)} MB")
        print(f"  스케일러 크기: {model_info.get('scaler_size_kb', 0)} KB")

    print("\n=== 테스트 완료 ===")

    return {
        'api_available': bool(api_client.malware_bazaar_key),
        'triage_available': bool(api_client.triage_key),
        'model_available': model_manager.is_model_available(),
        'data_sufficient': data_status['sufficient_data'],
        'data_status': data_status
    }


def setup_system_with_progress():
    """진행률 표시가 있는 시스템 초기 설정"""
    print("=== 시스템 초기 설정 ===")

    # 1단계: 시스템 테스트
    print("\n🔍 시스템 상태 확인 중...")
    test_results = test_system()

    # API 키가 없으면 안내
    if not test_results['api_available']:
        print("\n⚠️  MalwareBazaar API 키 설정이 필요합니다!")
        print("1. .env 파일을 생성하고 다음 내용을 추가하세요:")
        print("   MALWARE_BAZAAR_API_KEY=your_api_key_here")
        print("   TRIAGE_API_KEY=your_triage_key_here  # 선택사항")
        print("2. MalwareBazaar: https://bazaar.abuse.ch/api/")
        print("3. Triage: https://tria.ge/ (선택사항)")
        return False

    # 전체 진행 단계 계산
    total_steps = 1  # 기본 체크
    if not test_results['data_sufficient']:
        total_steps += 2  # 데이터 수집 (악성 + 정상)
    if not test_results['model_available']:
        total_steps += 3  # 모델 훈련 (전처리 + 훈련 + 저장)

    progress = ProgressTracker(total_steps)

    print(f"\n🚀 총 {total_steps}단계 작업을 시작합니다...\n")

    # 2단계: 데이터 수집
    if not test_results['data_sufficient']:
        print(f"⚠️  훈련 데이터가 부족합니다!")
        print(f"현재: 악성 {test_results['data_status']['malware_samples']}개, "
              f"정상 {test_results['data_status']['clean_samples']}개")

        response = input("\n데이터를 자동으로 수집하시겠습니까? (y/n): ").lower()
        if response != 'y':
            print("데이터 수집을 취소했습니다.")
            return False

        try:
            print("\n📥 데이터 수집 시작...")

            # 악성 샘플 수집
            progress.update("악성 샘플 수집 중 (MalwareBazaar + Triage)...")
            client = APIClient()
            malware_files = client.download_malware_samples(300)

            # 정상 샘플 생성
            progress.update("정상 샘플 생성 중...")
            clean_files = client.get_clean_samples(300)

            print(f"\n✅ 데이터 수집 완료: 악성 {len(malware_files)}개, 정상 {len(clean_files)}개")

        except Exception as e:
            print(f"\n❌ 데이터 수집 실패: {e}")
            return False

    # 3단계: 모델 훈련
    if not test_results['model_available'] or not test_results['data_sufficient']:
        print(f"\n🧠 모델 훈련을 시작합니다...")
        response = input("모델을 훈련하시겠습니까? (y/n): ").lower()
        if response != 'y':
            print("모델 훈련을 취소했습니다.")
            return False

        try:
            # 데이터 전처리
            progress.update("훈련 데이터 전처리 중...")

            # 모델 훈련
            progress.update("AI 모델 훈련 중 (앙상블 학습)...")
            success = train_model()

            if success:
                # 모델 저장
                progress.update("모델 저장 및 최적화 중...")
                print(f"\n✅ 모델 훈련 완료!")
            else:
                print(f"\n❌ 모델 훈련 실패!")
                return False

        except Exception as e:
            print(f"\n❌ 모델 훈련 실패: {e}")
            return False

    print(f"\n🎉 시스템 설정 완료!")
    print(f"이제 다음 명령어로 GUI를 실행할 수 있습니다:")
    print(f"python main.py")

    # 최종 상태 확인
    try:
        final_test = test_system()
        print(f"\n📊 최종 상태:")
        print(f"  - 총 샘플: {final_test['data_status']['malware_samples'] + final_test['data_status']['clean_samples']}개")
        print(f"  - 모델 상태: {'✅ 사용 가능' if final_test['model_available'] else '❌ 사용 불가'}")
    except Exception as e:
        print(f"최종 상태 확인 중 오류: {e}")

    return True


def setup_system():
    """기본 시스템 설정 (진행률 없음)"""
    return setup_system_with_progress()


def quick_test():
    """빠른 기능 테스트"""
    print("=== 빠른 기능 테스트 ===")

    model_manager = ModelManager()

    if not model_manager.is_model_available():
        print("❌ 모델이 없습니다. 먼저 setup_system()을 실행하세요.")
        return

    if not model_manager.load_model():
        print("❌ 모델 로드 실패")
        return

    print("✅ 모델 로드 성공")

    # 샘플 파일들로 테스트
    test_files = []

    # 악성 샘플 테스트
    if os.path.exists("sample/mecro"):
        malware_files = [
            os.path.join("sample/mecro", f)
            for f in os.listdir("sample/mecro")[:3]
            if os.path.isfile(os.path.join("sample/mecro", f))
        ]
        test_files.extend(malware_files)

    # 정상 샘플 테스트
    if os.path.exists("sample/clear"):
        clean_files = [
            os.path.join("sample/clear", f)
            for f in os.listdir("sample/clear")[:3]
            if os.path.isfile(os.path.join("sample/clear", f))
        ]
        test_files.extend(clean_files)

    if not test_files:
        print("❌ 테스트할 파일이 없습니다")
        return

    print(f"\n{len(test_files)}개 파일 예측 테스트:")

    for file_path in test_files:
        file_name = os.path.basename(file_path)
        file_type = "악성" if "mecro" in file_path else "정상"

        result = model_manager.predict_file(file_path)

        if "error" in result:
            print(f"❌ {file_name}: {result['error']}")
        else:
            prediction = result['prediction']
            confidence = result['confidence']
            correct = "✅" if (prediction == "악성" and file_type == "악성") or (
                    prediction == "정상" and file_type == "정상") else "❌"

            print(f"{correct} {file_name} (실제: {file_type}) → 예측: {prediction} (신뢰도: {confidence:.3f})")

    print("\n=== 테스트 완료 ===")


def check_git_auth():
    """Git 인증 문제 해결 안내"""
    print("\n🔧 Git 인증 문제 해결:")
    print("GitHub에서 패스워드 인증이 중단되었습니다.")
    print("Personal Access Token을 사용해야 합니다.")
    print("")
    print("해결 방법:")
    print("1. GitHub → Settings → Developer settings → Personal access tokens")
    print("2. Generate new token (classic)")
    print("3. repo 권한 체크")
    print("4. 생성된 토큰을 패스워드 대신 사용")
    print("")
    print("또는 SSH 키 설정:")
    print("ssh-keygen -t ed25519 -C 'your_email@example.com'")
    print("cat ~/.ssh/id_ed25519.pub  # 이 내용을 GitHub SSH keys에 추가")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "setup":
            setup_system()
        elif sys.argv[1] == "test":
            quick_test()
        elif sys.argv[1] == "git":
            check_git_auth()
        else:
            print("사용법: python test_api.py [setup|test|git]")
    else:
        test_system()