import requests
import os
import time
import hashlib
import sys
from typing import List, Dict, Optional
from dotenv import load_dotenv

load_dotenv()


class SimpleProgressTracker:
    """간결한 진행률 추적 클래스"""

    def __init__(self, total_target: int, operation_name: str = "다운로드"):
        self.total_target = total_target
        self.operation_name = operation_name
        self.start_time = time.time()
        self.completed_count = 0
        self.success_count = 0
        self.failed_count = 0
        self.file_types = {}

        try:
            import shutil
            self.terminal_width = shutil.get_terminal_size().columns
        except:
            self.terminal_width = 80

        self.progress_bar_width = min(40, self.terminal_width - 40)

    def update(self, success: bool = True, file_type: str = "unknown"):
        """진행률 업데이트 (간결한 버전)"""
        self.completed_count += 1

        if success:
            self.success_count += 1
            if file_type not in self.file_types:
                self.file_types[file_type] = 0
            self.file_types[file_type] += 1
        else:
            self.failed_count += 1

        progress_percentage = (self.completed_count / self.total_target) * 100
        filled_length = int(self.progress_bar_width * self.completed_count // self.total_target)
        bar = '█' * filled_length + '░' * (self.progress_bar_width - filled_length)

        elapsed_time = time.time() - self.start_time
        if elapsed_time > 0 and self.completed_count > 0:
            speed = self.completed_count / elapsed_time
            remaining = self.total_target - self.completed_count
            eta_seconds = remaining / speed if speed > 0 else 0
            eta_str = self._format_time(eta_seconds)
        else:
            eta_str = "계산 중"

        sys.stdout.write(
            f'\r[{bar}] {progress_percentage:.1f}% ({self.completed_count}/{self.total_target}) | ETA: {eta_str}')
        sys.stdout.flush()

    def _format_time(self, seconds: float) -> str:
        """시간 포맷팅"""
        if seconds <= 0:
            return "완료"
        elif seconds < 60:
            return f"{int(seconds)}초"
        elif seconds < 3600:
            return f"{int(seconds // 60)}분"
        else:
            return f"{int(seconds // 3600)}시간"

    def show_summary(self):
        """완료 요약 (간결한 버전)"""
        print("\n")
        elapsed_time = time.time() - self.start_time

        print(f"✅ {self.operation_name} 완료: {self.success_count}/{self.total_target}개 성공")
        if self.failed_count > 0:
            print(f"⚠️  실패: {self.failed_count}개")

        if self.file_types:
            type_summary = []
            for file_type, count in sorted(self.file_types.items()):
                if count > 0:
                    type_summary.append(f"{file_type.upper()}({count})")
            if type_summary:
                print(f"📊 수집 유형: {', '.join(type_summary)}")

        print(f"⏱️  소요시간: {self._format_time(elapsed_time)}")


class APIClient:
    def __init__(self):
        self.malware_bazaar_key = os.getenv('MALWARE_BAZAAR_API_KEY')
        self.triage_key = os.getenv('TRIAGE_API_KEY')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'DocumentSanitizer/2.0'})

    def test_malware_bazaar_connection(self) -> bool:
        """MalwareBazaar API 연결 테스트"""
        try:
            if not self.malware_bazaar_key:
                return False

            url = "https://mb-api.abuse.ch/api/v1/"
            headers = {"Auth-Key": self.malware_bazaar_key}
            data = {"query": "get_recent", "selector": "100"}
            response = self.session.post(url, data=data, headers=headers, timeout=10)

            if response.status_code == 200:
                result = response.json()
                return result.get("query_status") == "ok"
            return False
        except Exception:
            return False

    def test_triage_connection(self) -> bool:
        """Triage API 연결 테스트"""
        try:
            if not self.triage_key:
                return False
            headers = {"Authorization": f"Bearer {self.triage_key}"}
            url = "https://api.tria.ge/v0/samples"
            response = self.session.get(url, headers=headers, timeout=10)
            return response.status_code in [200, 401]
        except Exception:
            return False

    def download_malware_samples(self, count: int = 300) -> List[str]:
        """간결한 메시지로 악성코드 샘플 다운로드"""
        downloaded_files = []

        if not self.malware_bazaar_key:
            print("❌ MalwareBazaar API 키가 설정되지 않았습니다.")
            return downloaded_files

        print(f"📥 {count}개 문서형 악성코드 샘플 수집 중...")
        progress_tracker = SimpleProgressTracker(count, "악성 샘플 수집")

        try:
            os.makedirs("sample/mecro", exist_ok=True)

            # 1단계: 샘플 목록 수집
            document_samples = self._collect_document_samples()

            if not document_samples:
                print("❌ 수집 가능한 문서 샘플이 없습니다.")
                return downloaded_files

            # 2단계: 선택된 샘플 다운로드
            selected_samples = document_samples[:count]

            for i, sample in enumerate(selected_samples):
                if len(downloaded_files) >= count:
                    break

                file_path = self._download_single_sample(sample, i)
                if file_path:
                    downloaded_files.append(file_path)
                    file_type = self._get_file_type(sample.get("file_name", ""))
                    progress_tracker.update(success=True, file_type=file_type)
                else:
                    progress_tracker.update(success=False)

                time.sleep(1)  # API 제한 준수

        except Exception as e:
            print(f"\n❌ 수집 중 오류 발생: {str(e)}")

        progress_tracker.show_summary()
        return downloaded_files

    def _collect_document_samples(self) -> List[Dict]:
        """문서 샘플 목록 수집 (내부 처리)"""
        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            headers = {"Auth-Key": self.malware_bazaar_key}

            # 최근 샘플 조회
            data = {"query": "get_recent", "selector": "1000"}
            response = self.session.post(url, data=data, headers=headers, timeout=30)

            all_samples = []
            if response.status_code == 200:
                result = response.json()
                if result.get("query_status") == "ok":
                    all_samples = result.get("data", [])

            # 문서 타입 필터링
            document_samples = []
            document_extensions = ['.pdf', '.doc', '.docx', '.docm', '.xls', '.xlsx',
                                   '.xlsm', '.ppt', '.pptx', '.pptm', '.hwp', '.hwpx']

            for sample in all_samples:
                try:
                    file_name = str(sample.get("file_name", "")).lower()
                    file_type = str(sample.get("file_type", "")).lower()
                    mime_type = str(sample.get("file_type_mime", "")).lower()

                    # 문서 파일 여부 확인
                    is_document = (
                            any(ext in file_name for ext in document_extensions) or
                            any(doc_type in file_type for doc_type in ['pdf', 'word', 'excel', 'powerpoint', 'hwp']) or
                            any(mime_type.startswith(prefix) for prefix in
                                ['application/pdf', 'application/msword', 'application/vnd.ms-'])
                    )

                    if is_document:
                        document_samples.append(sample)

                except Exception:
                    continue

            return document_samples

        except Exception:
            return []

    def _download_single_sample(self, sample: Dict, index: int) -> Optional[str]:
        """단일 샘플 다운로드 (내부 처리)"""
        try:
            sha256_hash = sample.get("sha256_hash")
            file_name = sample.get("file_name") or f"sample_{index:03d}"

            if not sha256_hash:
                return None

            # 안전한 파일명 생성
            safe_filename = self._generate_safe_filename(file_name)

            # 파일 다운로드
            url = "https://mb-api.abuse.ch/api/v1/"
            headers = {"Auth-Key": self.malware_bazaar_key}
            data = {"query": "get_file", "sha256_hash": sha256_hash}

            response = self.session.post(url, data=data, headers=headers, timeout=60)

            if response.status_code == 200 and response.content:
                # JSON 오류 응답 확인
                try:
                    if response.content.startswith(b'{'):
                        return None
                except:
                    pass

                # ZIP 파일 저장 및 압축 해제
                zip_path = os.path.join("sample/mecro", f"{safe_filename}.zip")

                with open(zip_path, "wb") as f:
                    f.write(response.content)

                # 압축 해제 시도
                extracted_path = self._extract_zip_file(zip_path, safe_filename)

                if extracted_path:
                    return extracted_path
                else:
                    return zip_path  # 압축 해제 실패 시 ZIP 파일 유지

            return None

        except Exception:
            return None

    def _extract_zip_file(self, zip_path: str, target_filename: str) -> Optional[str]:
        """ZIP 파일 압축 해제"""
        try:
            # pyzipper 시도
            try:
                import pyzipper
                with pyzipper.AESZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.pwd = b'infected'
                    extracted_files = zip_ref.namelist()

                    if extracted_files:
                        zip_ref.extractall("sample/mecro")
                        old_path = os.path.join("sample/mecro", extracted_files[0])
                        new_path = os.path.join("sample/mecro", target_filename)

                        if os.path.exists(old_path):
                            if os.path.exists(new_path):
                                os.remove(new_path)
                            os.rename(old_path, new_path)
                            os.remove(zip_path)
                            return new_path

            except ImportError:
                pass
            except Exception:
                pass

            # 일반 zipfile 시도
            try:
                import zipfile
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.setpassword(b'infected')
                    extracted_files = zip_ref.namelist()

                    if extracted_files:
                        zip_ref.extractall("sample/mecro")
                        old_path = os.path.join("sample/mecro", extracted_files[0])
                        new_path = os.path.join("sample/mecro", target_filename)

                        if os.path.exists(old_path):
                            if os.path.exists(new_path):
                                os.remove(new_path)
                            os.rename(old_path, new_path)
                            os.remove(zip_path)
                            return new_path

            except Exception:
                pass

            return None

        except Exception:
            return None

    def _generate_safe_filename(self, original_name: str) -> str:
        """안전한 파일명 생성"""
        safe_chars = "".join(c for c in str(original_name) if c.isalnum() or c in '._-')
        return safe_chars[:50] if safe_chars else f"sample_{int(time.time())}"

    def _get_file_type(self, filename: str) -> str:
        """파일 타입 추출"""
        filename_lower = filename.lower()

        if '.pdf' in filename_lower:
            return "pdf"
        elif any(ext in filename_lower for ext in ['.doc', '.docx']):
            return "word"
        elif any(ext in filename_lower for ext in ['.xls', '.xlsx']):
            return "excel"
        elif any(ext in filename_lower for ext in ['.ppt', '.pptx']):
            return "powerpoint"
        elif '.hwp' in filename_lower:
            return "hwp"
        else:
            return "기타"

    def get_clean_samples(self, count: int = 300) -> List[str]:
        """정상 샘플 생성 (간결한 버전)"""
        clean_files = []
        os.makedirs("sample/clear", exist_ok=True)

        print(f"📄 {count}개 정상 문서 샘플 생성 중...")
        progress_tracker = SimpleProgressTracker(count, "정상 샘플 생성")

        try:
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import letter

            for i in range(count):
                file_path = f"sample/clear/clean_document_{i:03d}.pdf"

                c = canvas.Canvas(file_path, pagesize=letter)
                c.drawString(100, 750, f"Clean Document #{i + 1}")
                c.drawString(100, 730, "안전한 정상 문서입니다.")
                c.drawString(100, 710, f"생성일: {time.strftime('%Y-%m-%d %H:%M:%S')}")
                c.save()

                clean_files.append(file_path)
                progress_tracker.update(success=True, file_type="pdf")

                if i % 50 == 0:  # 50개마다 잠시 대기
                    time.sleep(0.01)

        except ImportError:
            # reportlab이 없으면 텍스트 파일로 생성
            for i in range(count):
                file_path = f"sample/clear/clean_document_{i:03d}.txt"

                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(f"Clean Document #{i + 1}\n")
                    f.write("안전한 정상 문서입니다.\n")
                    f.write(f"생성일: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

                clean_files.append(file_path)
                progress_tracker.update(success=True, file_type="txt")

        progress_tracker.show_summary()
        return clean_files

    def check_file_with_virustotal(self, file_path: str) -> Dict:
        """VirusTotal로 파일 검사"""
        if not hasattr(self, 'virustotal_key') or not self.virustotal_key:
            return {"error": "VirusTotal API 키가 설정되지 않았습니다"}

        try:
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            headers = {"x-apikey": self.virustotal_key}
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

            response = self.session.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                result = response.json()
                stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "clean": stats.get("harmless", 0),
                    "total": sum(stats.values()) if stats else 0
                }
            else:
                return {"error": f"조회 실패: {response.status_code}"}

        except Exception as e:
            return {"error": f"검사 중 오류: {str(e)}"}


def collect_training_data(malware_count: int = 300, clean_count: int = 300):
    """간결한 메시지로 훈련 데이터 수집"""
    client = APIClient()

    print("🚀 AI 모델 훈련용 데이터 수집 시작")
    print(f"📋 계획: 악성 {malware_count}개, 정상 {clean_count}개")

    start_time = time.time()

    # 악성 샘플 다운로드
    malware_files = client.download_malware_samples(malware_count)

    # 정상 샘플 생성
    clean_files = client.get_clean_samples(clean_count)

    elapsed_time = time.time() - start_time
    print(f"\n🎉 데이터 수집 완료!")
    print(f"✅ 결과: 악성 {len(malware_files)}개, 정상 {len(clean_files)}개")
    print(f"⏱️  총 소요시간: {int(elapsed_time // 60)}분 {int(elapsed_time % 60)}초")

    return malware_files, clean_files


if __name__ == "__main__":
    collect_training_data()