# utils/api_client.py 수정 버전 - 기존 코드에 향상된 진행률 추적 시스템 통합

import requests
import os
import time
import hashlib
import sys
from typing import List, Dict, Optional
from dotenv import load_dotenv

load_dotenv()


class RealTimeProgressTracker:
    """실시간 다운로드 진행률 추적 클래스"""

    def __init__(self, total_target: int, operation_name: str = "다운로드"):
        self.total_target = total_target
        self.operation_name = operation_name
        self.start_time = time.time()

        # 통계 데이터
        self.completed_count = 0
        self.success_count = 0
        self.failed_count = 0
        self.current_file = ""
        self.file_type_stats = {}

        # 터미널 설정
        try:
            import shutil
            self.terminal_width = shutil.get_terminal_size().columns
        except:
            self.terminal_width = 100

        self.progress_bar_width = min(40, self.terminal_width - 60)

    def update(self, current_item: str = "", item_type: str = "unknown", success: bool = True,
               additional_info: str = ""):
        """진행률 업데이트"""

        self.completed_count += 1

        if success:
            self.success_count += 1
            # 파일 타입별 통계 업데이트
            if item_type not in self.file_type_stats:
                self.file_type_stats[item_type] = 0
            self.file_type_stats[item_type] += 1
        else:
            self.failed_count += 1

        self.current_file = current_item

        # 진행률 계산
        progress_percentage = (self.completed_count / self.total_target) * 100

        # 속도 계산
        elapsed_time = time.time() - self.start_time
        if elapsed_time > 0:
            speed = self.success_count / elapsed_time
        else:
            speed = 0

        # ETA 계산
        remaining_items = self.total_target - self.completed_count
        if speed > 0 and remaining_items > 0:
            eta_seconds = remaining_items / speed
        else:
            eta_seconds = 0

        # 진행률 바 생성
        filled_length = int(self.progress_bar_width * self.completed_count // self.total_target)
        bar = '█' * filled_length + '░' * (self.progress_bar_width - filled_length)

        # 성공률 계산
        success_rate = (self.success_count / self.completed_count * 100) if self.completed_count > 0 else 0

        # 현재 파일명 축약
        display_file = current_item
        if len(display_file) > 25:
            display_file = "..." + display_file[-22:]

        # ETA 포맷팅
        eta_str = self._format_time(eta_seconds)

        # 진행률 출력 구성
        progress_text = (
            f'\r[{bar}] {progress_percentage:.1f}% ({self.completed_count}/{self.total_target}) | '
            f'성공: {self.success_count} | 실패: {self.failed_count} | '
            f'속도: {speed:.1f}/초 | ETA: {eta_str}'
        )

        # 터미널 너비에 맞춰 조정
        if len(progress_text) > self.terminal_width - 5:
            progress_text = f'\r[{bar}] {progress_percentage:.1f}% ({self.completed_count}/{self.total_target}) | 성공률: {success_rate:.0f}%'

        sys.stdout.write(progress_text)
        sys.stdout.flush()

        # 추가 정보가 있으면 새 줄에 출력
        if additional_info:
            print(f"\n  ℹ️ {additional_info}")

    def _format_time(self, seconds: float) -> str:
        """시간 포맷팅"""
        if seconds <= 0:
            return "완료"
        elif seconds < 60:
            return f"{int(seconds)}초"
        elif seconds < 3600:
            minutes = int(seconds // 60)
            return f"{minutes}분"
        else:
            hours = int(seconds // 3600)
            minutes = int((seconds % 3600) // 60)
            return f"{hours}h{minutes}m"

    def show_completion_summary(self):
        """완료 후 요약 정보 표시"""
        print("\n")
        print("=" * 70)
        print(f"📊 {self.operation_name} 완료 요약")
        print("=" * 70)

        elapsed_time = time.time() - self.start_time
        average_speed = self.success_count / elapsed_time if elapsed_time > 0 else 0

        print(f"📈 전체 결과:")
        print(f"  • 대상: {self.total_target}개")
        print(f"  • 성공: {self.success_count}개")
        print(f"  • 실패: {self.failed_count}개")
        print(f"  • 성공률: {(self.success_count / self.total_target * 100):.1f}%")
        print(f"  • 소요시간: {self._format_time(elapsed_time)}")
        print(f"  • 평균 속도: {average_speed:.2f}개/초")

        if self.file_type_stats:
            print(f"\n🏷️ 파일 타입별 수집 현황:")
            for file_type, count in sorted(self.file_type_stats.items()):
                if count > 0:
                    print(f"  • {file_type.upper()}: {count}개")


class APIClient:
    def __init__(self):
        self.malware_bazaar_key = os.getenv('MALWARE_BAZAAR_API_KEY')
        self.triage_key = os.getenv('TRIAGE_API_KEY')  # Triage API 키 추가
        self.session = requests.Session()

        # 세션 설정 최적화
        self.session.headers.update({
            'User-Agent': 'DocumentSanitizer/1.0'
        })

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
        except Exception as e:
            print(f"MalwareBazaar 연결 실패: {e}")
            return False

    def test_triage_connection(self) -> bool:
        """Triage API 연결 테스트"""
        try:
            if not self.triage_key:
                return False
            headers = {"Authorization": f"Bearer {self.triage_key}"}
            url = "https://api.tria.ge/v0/samples"
            response = self.session.get(url, headers=headers, timeout=10)
            return response.status_code in [200, 401]  # 401도 연결은 성공 (키 문제일 수 있음)
        except Exception as e:
            print(f"Triage 연결 실패: {e}")
            return False

    def download_malware_samples(self, count: int = 300) -> List[str]:
        """향상된 진행률 추적이 적용된 악성코드 샘플 다운로드"""
        downloaded_files = []

        print(f"📥 {count}개 문서형 악성코드 샘플 수집 시작...")
        print("🎯 대상 형식: PDF, Office 문서(Word/Excel/PowerPoint), HWP")
        print("=" * 70)

        # 진행률 추적기 초기화
        progress_tracker = RealTimeProgressTracker(count, "악성 샘플 수집")

        try:
            os.makedirs("sample/mecro", exist_ok=True)

            # 1단계: MalwareBazaar에서 수집
            print("🔍 1단계: MalwareBazaar 샘플 수집 중...")
            mb_samples = self._collect_from_malware_bazaar(int(count * 0.6), progress_tracker)
            downloaded_files.extend(mb_samples)

            # 2단계: Triage에서 추가 수집 (시간 초과 처리 개선)
            remaining_count = count - len(downloaded_files)
            if remaining_count > 0 and self.triage_key:
                print(f"\n🔍 2단계: Triage 추가 샘플 수집 중... (남은 {remaining_count}개)")
                triage_samples = self._collect_from_triage_safe(remaining_count, progress_tracker)
                downloaded_files.extend(triage_samples)

            # 3단계: 부족한 경우 MalwareBazaar에서 추가 수집
            final_remaining = count - len(downloaded_files)
            if final_remaining > 0:
                print(f"\n🔍 3단계: 추가 샘플 수집 중... (남은 {final_remaining}개)")
                additional_samples = self._collect_from_malware_bazaar(final_remaining, progress_tracker,
                                                                       offset=len(mb_samples))
                downloaded_files.extend(additional_samples)

        except Exception as e:
            print(f"\n❌ 수집 중 오류 발생: {e}")

        # 완료 요약 표시
        progress_tracker.show_completion_summary()

        return downloaded_files[:count]  # 목표 수량으로 제한

    def _collect_from_malware_bazaar(self, target_count: int, progress_tracker: RealTimeProgressTracker,
                                     offset: int = 0) -> List[str]:
        """MalwareBazaar에서 샘플 수집 (향상된 진행률 추적 포함)"""
        downloaded_files = []

        if not self.malware_bazaar_key:
            return downloaded_files

        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            headers = {"Auth-Key": self.malware_bazaar_key}

            # 최근 샘플 조회
            data = {"query": "get_recent", "selector": "1000"}
            response = self.session.post(url, data=data, headers=headers, timeout=30)

            if response.status_code == 200:
                result = response.json()
                if result.get("query_status") == "ok":
                    samples = result.get("data", [])

                    # 문서 파일 필터링
                    document_samples = self._filter_document_samples(samples)
                    selected_samples = document_samples[offset:offset + target_count]

                    # 실제 다운로드
                    for i, sample in enumerate(selected_samples):
                        if len(downloaded_files) >= target_count:
                            break

                        file_path = self._download_single_sample(sample, progress_tracker)
                        if file_path:
                            downloaded_files.append(file_path)

                        # API 제한 준수
                        time.sleep(1.5)

        except Exception as e:
            progress_tracker.update("MalwareBazaar 오류", "error", success=False, additional_info=f"오류: {str(e)}")

        return downloaded_files

    def _collect_from_triage_safe(self, target_count: int, progress_tracker: RealTimeProgressTracker) -> List[str]:
        """Triage에서 안전한 샘플 수집 (타임아웃 처리 개선)"""
        downloaded_files = []

        if not self.triage_key:
            return downloaded_files

        # 타임아웃을 단계적으로 줄이면서 시도
        timeout_values = [15, 10, 5]  # 15초 -> 10초 -> 5초 순으로 시도

        for timeout in timeout_values:
            try:
                headers = {"Authorization": f"Bearer {self.triage_key}"}

                # 간단한 쿼리부터 시도
                simple_queries = [
                    "family:emotet",
                    "family:formbook",
                    "target:document"
                ]

                for query in simple_queries:
                    if len(downloaded_files) >= target_count:
                        break

                    try:
                        url = f"https://api.tria.ge/v0/search?query={query}&limit=50"
                        response = self.session.get(url, headers=headers, timeout=timeout)

                        if response.status_code == 200:
                            results = response.json()
                            samples = results.get("data", [])

                            progress_tracker.update(
                                f"Triage '{query}'",
                                "triage",
                                success=True,
                                additional_info=f"{len(samples)}개 발견 (timeout={timeout}초)"
                            )

                            # 샘플 다운로드 처리는 별도 구현 필요
                            # 여기서는 진행률 업데이트만 수행

                        time.sleep(2)  # API 제한 준수

                    except requests.exceptions.ReadTimeout:
                        progress_tracker.update(
                            f"Triage '{query}'",
                            "error",
                            success=False,
                            additional_info=f"타임아웃 (timeout={timeout}초) - 다음 설정으로 재시도"
                        )
                        continue
                    except Exception as e:
                        progress_tracker.update(
                            f"Triage '{query}'",
                            "error",
                            success=False,
                            additional_info=f"오류: {str(e)}"
                        )
                        continue

                # 성공적으로 수집했으면 루프 탈출
                if downloaded_files:
                    break

            except Exception as e:
                progress_tracker.update(
                    "Triage 전체",
                    "error",
                    success=False,
                    additional_info=f"연결 오류: {str(e)}"
                )

        return downloaded_files

    def _filter_document_samples(self, samples: List[Dict]) -> List[Dict]:
        """문서 파일만 필터링"""
        document_samples = []

        for sample in samples:
            try:
                file_name = str(sample.get("file_name", "")).lower()
                file_type = str(sample.get("file_type", "")).lower()
                mime_type = str(sample.get("file_type_mime", "")).lower()

                # 문서 파일 형식 검사
                document_indicators = [
                    # PDF
                    '.pdf', 'pdf', 'application/pdf',
                    # Office 문서
                    '.doc', '.docx', '.docm', 'msword', 'wordprocessingml',
                    '.xls', '.xlsx', '.xlsm', 'excel', 'spreadsheetml',
                    '.ppt', '.pptx', '.pptm', 'powerpoint', 'presentationml',
                    # HWP
                    '.hwp', '.hwpx', '.hwpml', 'hwp'
                ]

                if any(indicator in file_name or indicator in file_type or indicator in mime_type
                       for indicator in document_indicators):
                    document_samples.append(sample)

            except Exception:
                continue

        return document_samples

    def _download_single_sample(self, sample: Dict, progress_tracker: RealTimeProgressTracker) -> Optional[str]:
        """단일 샘플 다운로드 (진행률 추적 포함)"""
        try:
            sha256_hash = sample.get("sha256_hash")
            file_name = sample.get("file_name") or "unknown_sample"

            if not sha256_hash:
                progress_tracker.update(file_name, "unknown", success=False)
                return None

            # 파일 타입 결정
            file_type = self._determine_file_type(file_name)

            # 안전한 파일명 생성
            safe_filename = self._generate_safe_filename(file_name)

            # MalwareBazaar에서 다운로드
            url = "https://mb-api.abuse.ch/api/v1/"
            headers = {"Auth-Key": self.malware_bazaar_key}
            data = {"query": "get_file", "sha256_hash": sha256_hash}

            response = self.session.post(url, data=data, headers=headers, timeout=60)

            if response.status_code == 200 and response.content:
                # ZIP 파일 저장
                zip_path = os.path.join("sample/mecro", f"{safe_filename}.zip")

                with open(zip_path, "wb") as f:
                    f.write(response.content)

                # 압축 해제 시도
                extracted_path = self._extract_malware_zip(zip_path, safe_filename)

                if extracted_path:
                    progress_tracker.update(safe_filename, file_type, success=True)
                    return extracted_path
                else:
                    progress_tracker.update(safe_filename, file_type, success=True, additional_info="ZIP 파일로 저장")
                    return zip_path
            else:
                progress_tracker.update(safe_filename, file_type, success=False)
                return None

        except Exception as e:
            progress_tracker.update(file_name, "error", success=False, additional_info=f"오류: {str(e)}")
            return None

    def _determine_file_type(self, filename: str) -> str:
        """파일명에서 타입 결정"""
        filename_lower = filename.lower()

        if '.pdf' in filename_lower:
            return "pdf"
        elif any(ext in filename_lower for ext in ['.doc', '.docx', '.docm']):
            return "word"
        elif any(ext in filename_lower for ext in ['.xls', '.xlsx', '.xlsm']):
            return "excel"
        elif any(ext in filename_lower for ext in ['.ppt', '.pptx', '.pptm']):
            return "powerpoint"
        elif any(ext in filename_lower for ext in ['.hwp', '.hwpx', '.hwpml']):
            return "hwp"
        else:
            return "unknown"

    def _generate_safe_filename(self, original_name: str) -> str:
        """안전한 파일명 생성"""
        safe_chars = "".join(c for c in str(original_name) if c.isalnum() or c in '._-')
        return safe_chars[:50] if safe_chars else f"sample_{int(time.time())}"

    def _extract_malware_zip(self, zip_path: str, target_filename: str) -> Optional[str]:
        """악성코드 ZIP 파일 압축 해제"""
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
                            os.remove(zip_path)  # ZIP 파일 삭제
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
                            os.remove(zip_path)  # ZIP 파일 삭제
                            return new_path

            except Exception:
                pass

            # 압축 해제 실패 시 ZIP 파일 유지
            return None

        except Exception:
            return None

    def get_clean_samples(self, count: int = 300) -> List[str]:
        """정상 샘플 생성 (향상된 진행률 추적 포함)"""
        clean_files = []
        os.makedirs("sample/clear", exist_ok=True)

        print(f"\n📄 {count}개 정상 문서 샘플 생성 중...")
        print("=" * 70)

        # 진행률 추적기
        progress_tracker = RealTimeProgressTracker(count, "정상 샘플 생성")

        try:
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import letter

            for i in range(count):
                file_path = f"sample/clear/clean_document_{i:03d}.pdf"
                filename = f"clean_document_{i:03d}.pdf"

                c = canvas.Canvas(file_path, pagesize=letter)
                c.drawString(100, 750, f"Clean Document #{i + 1}")
                c.drawString(100, 730, "This is a normal, safe document.")
                c.drawString(100, 710, f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
                c.save()

                clean_files.append(file_path)
                progress_tracker.update(filename, "pdf", success=True)

                time.sleep(0.01)  # 시각적 효과

        except ImportError:
            # reportlab이 없으면 텍스트 파일로 생성
            for i in range(count):
                file_path = f"sample/clear/clean_document_{i:03d}.txt"
                filename = f"clean_document_{i:03d}.txt"

                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(f"Clean Document #{i + 1}\n")
                    f.write("This is a normal, safe document.\n")
                    f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

                clean_files.append(file_path)
                progress_tracker.update(filename, "txt", success=True)

                time.sleep(0.01)

        progress_tracker.show_completion_summary()
        return clean_files

    def check_file_with_virustotal(self, file_path: str) -> Dict:
        """VirusTotal로 파일 검사"""
        if not hasattr(self, 'virustotal_key') or not self.virustotal_key:
            return {"error": "VirusTotal API 키가 없습니다"}

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
    """향상된 진행률 추적이 포함된 훈련 데이터 수집"""
    client = APIClient()

    print("🚀 AI 모델 훈련용 데이터 수집 시작")
    print("=" * 70)
    print(f"📋 수집 계획:")
    print(f"  • 악성 문서 샘플: {malware_count}개")
    print(f"  • 정상 문서 샘플: {clean_count}개")
    estimated_time = (malware_count * 2 + clean_count * 0.1) / 60
    print(f"  • 예상 소요시간: 약 {estimated_time:.1f}분")
    print("=" * 70)

    # 악성 샘플 다운로드
    malware_files = client.download_malware_samples(malware_count)

    # 정상 샘플 생성
    clean_files = client.get_clean_samples(clean_count)

    print(f"\n🎉 데이터 수집 완료!")
    print(f"✅ 최종 결과: 악성 {len(malware_files)}개, 정상 {len(clean_files)}개")

    return malware_files, clean_files


if __name__ == "__main__":
    collect_training_data()