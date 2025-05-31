# utils/virustotal_checker.py - 새로운 VirusTotal 전용 모듈

import os
import hashlib
import requests
import time
from typing import Dict, Any
from config import API_KEYS


class VirusTotalChecker:
    """VirusTotal API를 이용한 파일 검사"""

    def __init__(self):
        self.api_key = API_KEYS.get('virustotal')
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"x-apikey": self.api_key})

    def is_available(self) -> bool:
        """VirusTotal API 사용 가능 여부 확인"""
        return bool(self.api_key)

    def test_connection(self) -> bool:
        """API 연결 테스트"""
        if not self.api_key:
            return False

        try:
            response = self.session.get(f"{self.base_url}/users/current", timeout=10)
            return response.status_code == 200
        except:
            return False

    def calculate_file_hash(self, file_path: str) -> str:
        """파일의 SHA256 해시 계산"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            raise Exception(f"해시 계산 실패: {str(e)}")

    def check_file_by_hash(self, file_hash: str) -> Dict[str, Any]:
        """해시로 파일 검사 결과 조회"""
        if not self.api_key:
            return {"error": "VirusTotal API 키가 설정되지 않음"}

        try:
            url = f"{self.base_url}/files/{file_hash}"
            response = self.session.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                # 검사 결과 정리
                result = {
                    "found": True,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()) if stats else 0,
                    "scan_date": attributes.get("last_analysis_date"),
                    "file_names": attributes.get("names", [])
                }

                # 위험도 계산
                if result["total_engines"] > 0:
                    danger_score = (result["malicious"] + result["suspicious"]) / result["total_engines"]
                    result["danger_percentage"] = round(danger_score * 100, 1)
                else:
                    result["danger_percentage"] = 0.0

                # 판정 결과
                if result["malicious"] > 0:
                    result["verdict"] = "악성"
                elif result["suspicious"] > 3:  # 의심스러운 탐지가 3개 이상
                    result["verdict"] = "의심"
                else:
                    result["verdict"] = "안전"

                return result

            elif response.status_code == 404:
                return {
                    "found": False,
                    "verdict": "미등록",
                    "message": "VirusTotal 데이터베이스에 없는 파일"
                }
            else:
                return {"error": f"API 오류: HTTP {response.status_code}"}

        except Exception as e:
            return {"error": f"검사 중 오류: {str(e)}"}

    def upload_and_scan_file(self, file_path: str) -> Dict[str, Any]:
        """파일 업로드 후 검사 (큰 파일이나 새로운 파일용)"""
        if not self.api_key:
            return {"error": "VirusTotal API 키가 설정되지 않음"}

        try:
            # 파일 크기 확인 (32MB 제한)
            file_size = os.path.getsize(file_path)
            if file_size > 32 * 1024 * 1024:
                return {"error": "파일이 너무 큽니다 (32MB 제한)"}

            # 파일 업로드
            upload_url = f"{self.base_url}/files"

            with open(file_path, 'rb') as f:
                files = {"file": (os.path.basename(file_path), f)}
                response = self.session.post(upload_url, files=files, timeout=60)

            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get("data", {}).get("id")

                if analysis_id:
                    return {
                        "uploaded": True,
                        "analysis_id": analysis_id,
                        "message": "업로드 완료, 분석 대기 중"
                    }
                else:
                    return {"error": "업로드 응답에서 분석 ID를 찾을 수 없음"}
            else:
                return {"error": f"업로드 실패: HTTP {response.status_code}"}

        except Exception as e:
            return {"error": f"업로드 중 오류: {str(e)}"}

    def get_analysis_result(self, analysis_id: str) -> Dict[str, Any]:
        """분석 결과 조회"""
        if not self.api_key:
            return {"error": "VirusTotal API 키가 설정되지 않음"}

        try:
            url = f"{self.base_url}/analyses/{analysis_id}"
            response = self.session.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})

                # 분석 상태 확인
                status = attributes.get("status")
                if status == "completed":
                    stats = attributes.get("stats", {})

                    result = {
                        "completed": True,
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "total_engines": sum(stats.values()) if stats else 0
                    }

                    # 위험도 계산
                    if result["total_engines"] > 0:
                        danger_score = (result["malicious"] + result["suspicious"]) / result["total_engines"]
                        result["danger_percentage"] = round(danger_score * 100, 1)
                    else:
                        result["danger_percentage"] = 0.0

                    # 판정
                    if result["malicious"] > 0:
                        result["verdict"] = "악성"
                    elif result["suspicious"] > 3:
                        result["verdict"] = "의심"
                    else:
                        result["verdict"] = "안전"

                    return result
                else:
                    return {
                        "completed": False,
                        "status": status,
                        "message": "분석 진행 중..."
                    }
            else:
                return {"error": f"분석 결과 조회 실패: HTTP {response.status_code}"}

        except Exception as e:
            return {"error": f"분석 결과 조회 중 오류: {str(e)}"}

    def comprehensive_check(self, file_path: str) -> Dict[str, Any]:
        """종합적인 파일 검사 (해시 조회 -> 필요시 업로드)"""
        file_name = os.path.basename(file_path)

        try:
            # 1단계: 해시 계산
            file_hash = self.calculate_file_hash(file_path)

            # 2단계: 해시로 기존 검사 결과 조회
            hash_result = self.check_file_by_hash(file_hash)

            if hash_result.get("found"):
                # 기존 검사 결과 있음
                return {
                    "method": "hash_lookup",
                    "file_name": file_name,
                    "file_hash": file_hash,
                    **hash_result
                }
            elif hash_result.get("error"):
                return hash_result
            else:
                # 3단계: 새 파일이므로 업로드 후 검사
                upload_result = self.upload_and_scan_file(file_path)

                if upload_result.get("uploaded"):
                    return {
                        "method": "upload_scan",
                        "file_name": file_name,
                        "file_hash": file_hash,
                        "analysis_id": upload_result["analysis_id"],
                        "verdict": "분석 중",
                        "message": "새로운 파일로 업로드하여 분석 중입니다."
                    }
                else:
                    return upload_result

        except Exception as e:
            return {"error": f"종합 검사 중 오류: {str(e)}"}

    def format_result_message(self, result: Dict[str, Any]) -> str:
        """검사 결과를 사용자 친화적 메시지로 변환"""
        if "error" in result:
            return f"❌ 오류: {result['error']}"

        if result.get("method") == "hash_lookup":
            verdict = result.get("verdict", "알 수 없음")
            malicious = result.get("malicious", 0)
            total = result.get("total_engines", 0)
            danger_pct = result.get("danger_percentage", 0)

            if verdict == "악성":
                return f"🚨 VirusTotal: 악성 ({malicious}/{total} 엔진 탐지, 위험도: {danger_pct}%)"
            elif verdict == "의심":
                return f"⚠️ VirusTotal: 의심스러움 (위험도: {danger_pct}%)"
            elif verdict == "안전":
                return f"✅ VirusTotal: 안전 ({total}개 엔진 검사 완료)"
            else:
                return f"❓ VirusTotal: {verdict}"

        elif result.get("method") == "upload_scan":
            return f"📤 VirusTotal: 새 파일 업로드 완료, 분석 대기 중..."

        elif result.get("verdict") == "미등록":
            return f"❓ VirusTotal: 데이터베이스에 없는 새로운 파일"

        else:
            return f"❓ VirusTotal: 알 수 없는 결과"


def create_virustotal_checker():
    """VirusTotal 체커 인스턴스 생성"""
    return VirusTotalChecker()


if __name__ == "__main__":
    # 테스트 코드
    checker = VirusTotalChecker()

    print("=== VirusTotal 체커 테스트 ===")
    print(f"API 사용 가능: {checker.is_available()}")

    if checker.is_available():
        print(f"연결 테스트: {checker.test_connection()}")

        # 샘플 파일이 있다면 테스트
        if os.path.exists("sample/mecro"):
            files = [f for f in os.listdir("sample/mecro") if os.path.isfile(os.path.join("sample/mecro", f))]
            if files:
                test_file = os.path.join("sample/mecro", files[0])
                print(f"\n테스트 파일: {files[0]}")

                result = checker.comprehensive_check(test_file)
                message = checker.format_result_message(result)
                print(f"검사 결과: {message}")
    else:
        print("VirusTotal API 키가 설정되지 않았습니다.")