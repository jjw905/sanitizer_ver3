import os
from dotenv import load_dotenv
from utils.api_client import APIClient, collect_training_data
from utils.model_manager import ModelManager
from utils.model_trainer import train_model


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

    # VirusTotal API 테스트
    if api_client.virustotal_key:
        print("  ✔ VirusTotal API 키 설정됨")
        if api_client.test_virustotal_connection():
            print("  ✔ VirusTotal API 연결 성공")
        else:
            print("  ✗ VirusTotal API 연결 실패")
    else:
        print("  ✗ VirusTotal API 키 없음")

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
        print("  ⚠ 훈련 데이터 부족 (각각 최소 10개 필요)")

    # 4. 모델 정보 출력
    model_info = model_manager.get_model_info()
    if model_info['model_available']:
        print(f"\n4. 모델 정보")
        print(f"  모델 크기: {model_info.get('model_size_mb', 0)} MB")
        print(f"  스케일러 크기: {model_info.get('scaler_size_kb', 0)} KB")

    print("\n=== 테스트 완료 ===")

    return {
        'api_available': bool(api_client.malware_bazaar_key and api_client.virustotal_key),
        'model_available': model_manager.is_model_available(),
        'data_sufficient': data_status['sufficient_data'],
        'data_status': data_status
    }


def setup_system():
    """시스템 초기 설정"""
    print("=== 시스템 초기 설정 ===")

    test_results = test_system()

    # API 키가 없으면 안내
    if not test_results['api_available']:
        print("\n⚠️  API 키 설정이 필요합니다!")
        print("1. .env 파일을 생성하고 다음 내용을 추가하세요:")
        print("   MALWARE_BAZAAR_API_KEY=your_api_key_here")
        print("   VIRUSTOTAL_API_KEY=your_api_key_here")
        print("2. MalwareBazaar: https://bazaar.abuse.ch/api/")
        print("3. VirusTotal: https://www.virustotal.com/gui/my-apikey")
        return False

    # 데이터가 부족하면 수집
    if not test_results['data_sufficient']:
        print(f"\n⚠️  훈련 데이터가 부족합니다!")
        print(f"현재: 악성 {test_results['data_status']['malware_samples']}개, "
              f"정상 {test_results['data_status']['clean_samples']}개")

        response = input("데이터를 자동으로 수집하시겠습니까? (y/n): ").lower()
        if response == 'y':
            try:
                print("데이터 수집 중... (시간이 걸릴 수 있습니다)")
                collect_training_data(malware_count=15, clean_count=15)
                print("✅ 데이터 수집 완료!")
            except Exception as e:
                print(f"❌ 데이터 수집 실패: {e}")
                return False

    # 모델이 없으면 훈련
    if not test_results['model_available']:
        print(f"\n⚠️  훈련된 모델이 없습니다!")
        response = input("모델을 훈련하시겠습니까? (y/n): ").lower()
        if response == 'y':
            try:
                print("모델 훈련 중... (시간이 걸릴 수 있습니다)")
                success = train_model()
                if success:
                    print("✅ 모델 훈련 완료!")
                else:
                    print("❌ 모델 훈련 실패!")
                    return False
            except Exception as e:
                print(f"❌ 모델 훈련 실패: {e}")
                return False

    print("\n✅ 시스템 설정 완료!")
    print("이제 main.py를 실행하여 GUI를 사용할 수 있습니다.")
    return True


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


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        if sys.argv[1] == "setup":
            setup_system()
        elif sys.argv[1] == "test":
            quick_test()
        else:
            print("사용법: python test_api.py [setup|test]")
    else:
        test_system()