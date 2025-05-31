# utils/api_client.py - 개선된 버전 (균형잡힌 파일 형식 수집)

import requests
import os
import time
import hashlib
import subprocess
from typing import List, Dict, Optional
from dotenv import load_dotenv
from collections import defaultdict

load_dotenv()


class BalancedAPIClient:
    def __init__(self):
        self.malware_bazaar_key = os.getenv('MALWARE_BAZAAR_API_KEY')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.triage_key = os.getenv('TRIAGE_API_KEY')

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DocSanitizer/2.0'
        })

        # 파일 형식별 목표 수량 (균형잡힌 수집)
        self.file_type_targets = {
            'pdf': 60,  # PDF 줄임
            'docx': 50,  # Word 문서
            'xlsx': 40,  # Excel 문서
            'pptx': 30,  # PowerPoint 문서
            'hwp': 40,  # 한글 문서
            'rtf': 20,  # RTF 문서
            'other': 60  # 기타 (doc, xls, ppt 등)
        }

        # 다운로드 통계 (형식별)
        self.download_stats = {
            'by_format': defaultdict(int),
            'malwarebazaar_count': 0,
            'triage_count': 0,
            'failed_downloads': 0,
            'failed_extractions': 0,
            'duplicate_hashes': 0,
            'format_distribution': defaultdict(int)
        }

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

    def test_virustotal_connection(self) -> bool:
        """VirusTotal API 연결 테스트"""
        try:
            if not self.virustotal_key:
                return False
            headers = {"x-apikey": self.virustotal_key}
            url = "https://www.virustotal.com/api/v3/users/current"
            response = self.session.get(url, headers=headers, timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"VirusTotal 연결 실패: {e}")
            return False

    def test_triage_connection(self) -> bool:
        """Tria.ge API 연결 테스트 (개선된 버전)"""
        try:
            if not self.triage_key:
                return False
            headers = {"Authorization": f"Bearer {self.triage_key}"}
            url = "https://api.tria.ge/v0/samples"

            # 타임아웃을 짧게 설정하고 재시도
            for attempt in range(3):
                try:
                    response = self.session.get(url, headers=headers, timeout=10)
                    if response.status_code in [200, 401, 403]:
                        return True
                except requests.exceptions.Timeout:
                    print(f"Tria.ge 연결 시도 {attempt + 1}/3 타임아웃")
                    time.sleep(2)
                    continue
                except Exception as e:
                    print(f"Tria.ge 연결 오류: {e}")
                    return False

            return False
        except Exception as e:
            print(f"Tria.ge 연결 실패: {e}")
            return False

    def download_malware_samples_balanced(self, target_count: int = 300) -> List[str]:
        """균형잡힌 악성코드 샘플 다운로드"""
        downloaded_files = []
        downloaded_hashes = set()

        print(f"🎯 목표: {target_count}개 문서형 악성코드 샘플 수집 (균형잡힌 형식)")
        print("=" * 60)

        # 현재 목표별 진행상황 출력
        print("📋 파일 형식별 목표:")
        for file_type, target in self.file_type_targets.items():
            print(f"  {file_type.upper()}: {target}개")

        # 1단계: MalwareBazaar에서 균형잡힌 수집
        if self.malware_bazaar_key:
            print("\n📋 MalwareBazaar에서 균형잡힌 샘플 수집 중...")
            mb_files = self._download_from_malwarebazaar_balanced(downloaded_hashes)
            downloaded_files.extend(mb_files)
            self.download_stats['malwarebazaar_count'] = len(mb_files)
            print(f"   ✅ MalwareBazaar: {len(mb_files)}개 수집")

        # 2단계: 부족한 형식을 Tria.ge에서 보완
        remaining_needs = self._calculate_remaining_needs()
        total_remaining = sum(remaining_needs.values())

        if total_remaining > 0 and self.triage_key:
            print(f"\n🔬 Tria.ge에서 부족한 형식 {total_remaining}개 추가 수집 중...")
            triage_files = self._download_from_triage_balanced(remaining_needs, downloaded_hashes)
            downloaded_files.extend(triage_files)
            self.download_stats['triage_count'] = len(triage_files)
            print(f"   ✅ Tria.ge: {len(triage_files)}개 수집")

        # 최종 통계 출력
        self._print_balanced_statistics(downloaded_files, target_count)

        return downloaded_files

    def _download_from_malwarebazaar_balanced(self, downloaded_hashes: set) -> List[str]:
        """MalwareBazaar에서 균형잡힌 샘플 수집"""
        downloaded_files = []
        format_counts = defaultdict(int)

        if not self.malware_bazaar_key:
            return downloaded_files

        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            headers = {"Auth-Key": self.malware_bazaar_key}

            # 형식별 태그 매핑 (더 구체적으로)
            format_tags = {
                'pdf': ['pdf', 'adobe'],
                'docx': ['docx', 'word', 'document'],
                'xlsx': ['xlsx', 'excel', 'spreadsheet'],
                'pptx': ['pptx', 'powerpoint', 'presentation'],
                'hwp': ['hwp', 'hancom'],
                'rtf': ['rtf'],
                'other': ['doc', 'xls', 'ppt', 'office', 'macro']
            }

            # 각 형식별로 태그 검색
            for file_format, tags in format_tags.items():
                target_count = self.file_type_targets.get(file_format, 20)
                print(f"  └ {file_format.upper()} 형식 수집 중 (목표: {target_count}개)...")

                for tag in tags:
                    if format_counts[file_format] >= target_count:
                        break

                    try:
                        print(f"    '{tag}' 태그 검색...")
                        tag_data = {"query": "get_taginfo", "tag": tag, "limit": "100"}
                        tag_response = self.session.post(url, data=tag_data, headers=headers, timeout=30)

                        if tag_response.status_code == 200:
                            tag_result = tag_response.json()
                            if tag_result.get("query_status") == "ok":
                                samples = tag_result.get("data", [])

                                # 해당 형식의 파일만 필터링
                                format_samples = self._filter_samples_by_format(samples, file_format)

                                # 다운로드 실행
                                downloaded = self._download_samples_batch(
                                    format_samples,
                                    file_format,
                                    target_count - format_counts[file_format],
                                    downloaded_hashes
                                )

                                downloaded_files.extend(downloaded)
                                format_counts[file_format] += len(downloaded)
                                self.download_stats['format_distribution'][file_format] += len(downloaded)

                                print(f"      ✓ {len(downloaded)}개 다운로드 (누적: {format_counts[file_format]}개)")

                        time.sleep(2)  # API 제한 대응

                    except Exception as e:
                        print(f"      ❌ '{tag}' 검색 실패: {e}")
                        continue

                print(f"    {file_format.upper()} 완료: {format_counts[file_format]}개")

        except Exception as e:
            print(f"MalwareBazaar 균형 수집 오류: {e}")

        return downloaded_files

    def _download_from_triage_balanced(self, remaining_needs: Dict[str, int], downloaded_hashes: set) -> List[str]:
        """Tria.ge에서 부족한 형식을 균형있게 수집 (개선된 연결 안정성)"""
        downloaded_files = []

        if not self.triage_key:
            return downloaded_files

        try:
            headers = {"Authorization": f"Bearer {self.triage_key}"}

            # 형식별 쿼리 매핑 (더 안정적인 쿼리)
            format_queries = {
                'pdf': ['file:pdf', 'tag:pdf'],
                'docx': ['file:docx', 'file:doc'],
                'xlsx': ['file:xlsx', 'file:xls'],
                'pptx': ['file:pptx', 'file:ppt'],
                'hwp': ['file:hwp'],
                'rtf': ['file:rtf'],
                'other': ['tag:office', 'tag:macro']
            }

            for file_format, needed_count in remaining_needs.items():
                if needed_count <= 0:
                    continue

                print(f"  └ {file_format.upper()} 형식 {needed_count}개 추가 수집 중...")
                queries = format_queries.get(file_format, ['tag:office'])

                downloaded_for_format = 0

                for query in queries:
                    if downloaded_for_format >= needed_count:
                        break

                    try:
                        print(f"    '{query}' 검색 중...")

                        # 개선된 연결 처리 (재시도 로직)
                        sample_ids = self._search_triage_with_retry(query, headers)

                        if sample_ids:
                            print(f"      {len(sample_ids)}개 샘플 발견")

                            # 필요한 만큼만 다운로드
                            remaining = needed_count - downloaded_for_format
                            selected_ids = sample_ids[:remaining]

                            # 실제 다운로드
                            for sample_id in selected_ids:
                                if downloaded_for_format >= needed_count:
                                    break

                                file_path = self._download_triage_sample_safe(sample_id, file_format, headers,
                                                                              downloaded_hashes)

                                if file_path:
                                    downloaded_files.append(file_path)
                                    downloaded_for_format += 1
                                    self.download_stats['format_distribution'][file_format] += 1
                                    print(f"      ✓ {sample_id} 다운로드 완료")

                                time.sleep(3)  # 안정성을 위한 대기

                        time.sleep(5)  # 쿼리 간 대기

                    except Exception as e:
                        print(f"      ❌ '{query}' 검색 실패: {e}")
                        continue

                print(f"    {file_format.upper()} 추가 수집 완료: {downloaded_for_format}개")

        except Exception as e:
            print(f"Tria.ge 균형 수집 오류: {e}")

        return downloaded_files

    def _search_triage_with_retry(self, query: str, headers: dict, max_retries: int = 3) -> List[str]:
        """Tria.ge 검색 (재시도 로직 포함)"""
        for attempt in range(max_retries):
            try:
                search_url = f"https://api.tria.ge/v0/search?query={query}&limit=30"
                response = self.session.get(search_url, headers=headers, timeout=20)  # 타임아웃 줄임

                if response.status_code == 200:
                    result = response.json()
                    samples = result.get("data", [])
                    return [sample.get("id") for sample in samples if sample.get("id")]

                elif response.status_code == 429:  # Rate limit
                    print(f"      요청 제한 도달, {30}초 대기...")
                    time.sleep(30)
                    continue

                else:
                    print(f"      HTTP {response.status_code} 응답")

            except requests.exceptions.Timeout:
                print(f"      타임아웃 (시도 {attempt + 1}/{max_retries})")
                time.sleep(10 * (attempt + 1))  # 점진적 대기
                continue

            except Exception as e:
                print(f"      검색 오류: {e}")
                time.sleep(5)
                continue

        return []

    def _download_triage_sample_safe(self, sample_id: str, file_format: str, headers: dict, downloaded_hashes: set) -> \
    Optional[str]:
        """Tria.ge 샘플 안전한 다운로드"""
        try:
            download_url = f"https://api.tria.ge/v0/samples/{sample_id}/sample"

            # 타임아웃을 늘리고 재시도
            for attempt in range(2):
                try:
                    dl_response = self.session.get(download_url, headers=headers, timeout=60)

                    if dl_response.status_code == 200 and dl_response.content:
                        # 중복 확인
                        file_hash = hashlib.sha256(dl_response.content).hexdigest()
                        if file_hash in downloaded_hashes:
                            self.download_stats['duplicate_hashes'] += 1
                            return None

                        # 파일 저장
                        filename = f"triage_{file_format}_{sample_id}"
                        file_path = os.path.join("sample/mecro", filename)

                        os.makedirs("sample/mecro", exist_ok=True)
                        with open(file_path, "wb") as f:
                            f.write(dl_response.content)

                        downloaded_hashes.add(file_hash)
                        return file_path

                    elif dl_response.status_code == 404:
                        return None  # 샘플이 더 이상 존재하지 않음

                    else:
                        print(f"        다운로드 실패: HTTP {dl_response.status_code}")

                except requests.exceptions.Timeout:
                    print(f"        다운로드 타임아웃 (시도 {attempt + 1}/2)")
                    time.sleep(5)
                    continue

                break

            self.download_stats['failed_downloads'] += 1
            return None

        except Exception as e:
            print(f"        다운로드 오류: {e}")
            self.download_stats['failed_downloads'] += 1
            return None

    def _filter_samples_by_format(self, samples: List[dict], target_format: str) -> List[dict]:
        """샘플을 파일 형식별로 필터링"""
        filtered = []

        for sample in samples:
            file_name = sample.get("file_name", "").lower()
            file_type = sample.get("file_type", "").lower()

            if target_format == 'pdf':
                if '.pdf' in file_name or 'pdf' in file_type:
                    filtered.append(sample)
            elif target_format == 'docx':
                if any(ext in file_name for ext in ['.docx', '.docm']) or 'word' in file_type:
                    filtered.append(sample)
            elif target_format == 'xlsx':
                if any(ext in file_name for ext in ['.xlsx', '.xlsm']) or 'excel' in file_type:
                    filtered.append(sample)
            elif target_format == 'pptx':
                if any(ext in file_name for ext in ['.pptx', '.pptm']) or 'powerpoint' in file_type:
                    filtered.append(sample)
            elif target_format == 'hwp':
                if any(ext in file_name for ext in ['.hwp', '.hwpx']) or 'hwp' in file_type:
                    filtered.append(sample)
            elif target_format == 'rtf':
                if '.rtf' in file_name or 'rtf' in file_type:
                    filtered.append(sample)
            elif target_format == 'other':
                if any(ext in file_name for ext in ['.doc', '.xls', '.ppt']) or \
                        any(t in file_type for t in ['document', 'spreadsheet', 'presentation']):
                    filtered.append(sample)

        return filtered

    def _download_samples_batch(self, samples: List[dict], file_format: str, max_count: int, downloaded_hashes: set) -> \
    List[str]:
        """샘플 배치 다운로드"""
        downloaded_files = []

        for i, sample in enumerate(samples[:max_count]):
            try:
                sha256_hash = sample.get("sha256_hash")
                file_name = sample.get("file_name") or f"{file_format}_mb_{i:04d}"

                if not sha256_hash or sha256_hash in downloaded_hashes:
                    continue

                # 안전한 파일명 생성
                safe_filename = self._create_safe_filename(file_name, file_format, i)

                # 파일 다운로드
                download_data = {"query": "get_file", "sha256_hash": sha256_hash}
                url = "https://mb-api.abuse.ch/api/v1/"
                headers = {"Auth-Key": self.malware_bazaar_key}

                dl_response = self.session.post(url, data=download_data, headers=headers, timeout=60)

                if dl_response.status_code == 200 and dl_response.content:
                    zip_path = os.path.join("sample/mecro", f"{safe_filename}.zip")

                    os.makedirs("sample/mecro", exist_ok=True)
                    with open(zip_path, "wb") as f:
                        f.write(dl_response.content)

                    # 압축 해제
                    extracted = self._extract_malware_zip_enhanced(zip_path, safe_filename)

                    if extracted:
                        downloaded_files.append(extracted)
                        downloaded_hashes.add(sha256_hash)
                        if os.path.exists(zip_path):
                            os.remove(zip_path)
                    else:
                        # 압축 해제 실패해도 ZIP 파일 보관
                        downloaded_files.append(zip_path)
                        downloaded_hashes.add(sha256_hash)
                        self.download_stats['failed_extractions'] += 1
                else:
                    self.download_stats['failed_downloads'] += 1

                time.sleep(1)  # API 제한 대응

            except Exception as e:
                print(f"        배치 다운로드 오류: {e}")
                self.download_stats['failed_downloads'] += 1
                continue

        return downloaded_files

    def _calculate_remaining_needs(self) -> Dict[str, int]:
        """형식별 부족한 샘플 수 계산"""
        remaining = {}

        for file_format, target in self.file_type_targets.items():
            current_count = self.download_stats['format_distribution'][file_format]
            needed = max(0, target - current_count)
            remaining[file_format] = needed

        return remaining

    def _create_safe_filename(self, original_name: str, file_format: str, index: int) -> str:
        """안전한 파일명 생성"""
        safe_chars = "".join(c for c in str(original_name) if c.isalnum() or c in '._-')
        safe_name = safe_chars[:30] if safe_chars else f"{file_format}_{index:04d}"
        return f"{file_format}_{safe_name}"

    def _extract_malware_zip_enhanced(self, zip_path: str, target_filename: str) -> Optional[str]:
        """강화된 압축 해제"""
        passwords = [
            b'infected', b'malware', b'virus', b'password', b'',
            b'123456', b'abuse.ch', b'sample', b'test'
        ]

        extraction_methods = [
            ("pyzipper", self._extract_with_pyzipper),
            ("zipfile", self._extract_with_zipfile),
            ("7zip", self._extract_with_7zip)
        ]

        for method_name, extract_func in extraction_methods:
            try:
                result = extract_func(zip_path, target_filename, passwords)
                if result:
                    return result
            except Exception:
                continue

        return None

    def _extract_with_pyzipper(self, zip_path: str, target_filename: str, passwords: list) -> Optional[str]:
        """pyzipper로 압축 해제"""
        try:
            import pyzipper

            for password in passwords:
                try:
                    with pyzipper.AESZipFile(zip_path, 'r') as zip_ref:
                        if password:
                            zip_ref.setpassword(password)

                        extracted_files = zip_ref.namelist()
                        if extracted_files:
                            zip_ref.extractall("sample/mecro")

                            old_path = os.path.join("sample/mecro", extracted_files[0])
                            new_path = os.path.join("sample/mecro", target_filename)

                            if os.path.exists(old_path):
                                if os.path.exists(new_path):
                                    os.remove(new_path)
                                os.rename(old_path, new_path)
                                return new_path

                except Exception:
                    continue

        except ImportError:
            pass

        return None

    def _extract_with_zipfile(self, zip_path: str, target_filename: str, passwords: list) -> Optional[str]:
        """기본 zipfile로 압축 해제"""
        try:
            import zipfile

            for password in passwords:
                try:
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        if password:
                            zip_ref.setpassword(password)

                        extracted_files = zip_ref.namelist()
                        if extracted_files:
                            zip_ref.extractall("sample/mecro")

                            old_path = os.path.join("sample/mecro", extracted_files[0])
                            new_path = os.path.join("sample/mecro", target_filename)

                            if os.path.exists(old_path):
                                if os.path.exists(new_path):
                                    os.remove(new_path)
                                os.rename(old_path, new_path)
                                return new_path

                except Exception:
                    continue

        except Exception:
            pass

        return None

    def _extract_with_7zip(self, zip_path: str, target_filename: str, passwords: list) -> Optional[str]:
        """7zip으로 압축 해제"""
        try:
            for password in passwords:
                try:
                    password_str = password.decode() if password else ""

                    if password_str:
                        cmd = ['7z', 'x', zip_path, f'-p{password_str}', '-o./sample/mecro/', '-y']
                    else:
                        cmd = ['7z', 'x', zip_path, '-o./sample/mecro/', '-y']

                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

                    if result.returncode == 0:
                        # 성공적으로 압축 해제됨
                        extracted_files = []
                        for f in os.listdir("sample/mecro"):
                            if f != os.path.basename(zip_path) and not f.startswith('.'):
                                extracted_files.append(f)

                        if extracted_files:
                            old_path = os.path.join("sample/mecro", extracted_files[0])
                            new_path = os.path.join("sample/mecro", target_filename)

                            if os.path.exists(old_path):
                                if os.path.exists(new_path):
                                    os.remove(new_path)
                                os.rename(old_path, new_path)
                                return new_path

                except Exception:
                    continue

        except Exception:
            pass

        return None

    def _print_balanced_statistics(self, downloaded_files: list, target_count: int):
        """균형잡힌 다운로드 통계 출력"""
        actual_count = len(downloaded_files)
        success_rate = (actual_count / target_count) * 100 if target_count > 0 else 0

        print("\n" + "=" * 70)
        print("📊 균형잡힌 다운로드 결과 통계")
        print("=" * 70)
        print(f"🎯 목표 샘플 수: {target_count}개")
        print(f"✅ 실제 다운로드: {actual_count}개")
        print(f"📈 달성률: {success_rate:.1f}%")

        print(f"\n📋 파일 형식별 수집 결과:")
        for file_format, target in self.file_type_targets.items():
            actual = self.download_stats['format_distribution'][file_format]
            percentage = (actual / target) * 100 if target > 0 else 0
            print(f"  {file_format.upper():>5}: {actual:>3}개 / {target:>3}개 ({percentage:>5.1f}%)")

        print(f"\n📋 소스별 수집:")
        print(f"  MalwareBazaar: {self.download_stats['malwarebazaar_count']}개")
        print(f"  Tria.ge: {self.download_stats['triage_count']}개")
        print(f"❌ 다운로드 실패: {self.download_stats['failed_downloads']}개")
        print(f"🗜️ 압축해제 실패: {self.download_stats['failed_extractions']}개")
        print(f"🔄 중복 제거: {self.download_stats['duplicate_hashes']}개")

        # 형식별 균형성 평가
        balance_score = self._calculate_balance_score()
        print(
            f"\n⚖️  형식 균형성 점수: {balance_score:.1f}/10 {'(우수)' if balance_score >= 7 else '(개선필요)' if balance_score >= 4 else '(불균형)'}")

    def _calculate_balance_score(self) -> float:
        """형식별 균형성 점수 계산 (1-10)"""
        if not self.file_type_targets:
            return 0.0

        scores = []
        for file_format, target in self.file_type_targets.items():
            if target > 0:
                actual = self.download_stats['format_distribution'][file_format]
                ratio = min(actual / target, 1.0)  # 목표 대비 달성률 (최대 1.0)
                scores.append(ratio)

        if not scores:
            return 0.0

        # 평균 달성률 * 10 + 편차 보정
        avg_score = sum(scores) / len(scores)
        variance = sum((score - avg_score) ** 2 for score in scores) / len(scores)
        balance_penalty = min(variance * 5, 3)  # 편차가 클수록 점수 감점

        return max(0.0, min(10.0, (avg_score * 10) - balance_penalty))

    def check_file_with_virustotal(self, file_path: str) -> Dict:
        """VirusTotal로 파일 상세 검사"""
        if not self.virustotal_key:
            return {"error": "VirusTotal API 키가 설정되지 않았습니다"}

        try:
            # 파일 해시 계산
            with open(file_path, "rb") as f:
                file_content = f.read()
                file_hash = hashlib.sha256(file_content).hexdigest()

            headers = {"x-apikey": self.virustotal_key}

            # 먼저 해시로 기존 분석 결과 조회
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            response = self.session.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                # 기존 분석 결과 있음
                result = response.json()
                attributes = result.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": sum(stats.values()) if stats else 0,
                    "scan_date": attributes.get("last_analysis_date"),
                    "file_hash": file_hash,
                    "analysis_type": "existing"
                }

            elif response.status_code == 404:
                # 파일이 VT에 없음 - 새로 업로드해서 분석
                print(f"파일이 VirusTotal에 없음. 새로 업로드하여 분석...")

                # 파일 크기 확인 (VT는 32MB 제한)
                file_size = len(file_content)
                if file_size > 32 * 1024 * 1024:  # 32MB
                    return {"error": f"파일 크기가 너무 큽니다 ({file_size / (1024 * 1024):.1f}MB). VirusTotal 제한: 32MB"}

                # 파일 업로드
                upload_url = "https://www.virustotal.com/api/v3/files"
                files = {"file": (os.path.basename(file_path), file_content)}

                upload_response = self.session.post(upload_url, headers=headers, files=files, timeout=60)

                if upload_response.status_code == 200:
                    upload_result = upload_response.json()
                    analysis_id = upload_result.get("data", {}).get("id")

                    if analysis_id:
                        # 분석 완료까지 대기 (최대 2분)
                        print("VirusTotal 분석 대기 중...")
                        for attempt in range(24):  # 5초씩 24번 = 2분
                            time.sleep(5)

                            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                            analysis_response = self.session.get(analysis_url, headers=headers, timeout=30)

                            if analysis_response.status_code == 200:
                                analysis_result = analysis_response.json()
                                attributes = analysis_result.get("data", {}).get("attributes", {})

                                if attributes.get("status") == "completed":
                                    stats = attributes.get("stats", {})
                                    return {
                                        "malicious": stats.get("malicious", 0),
                                        "suspicious": stats.get("suspicious", 0),
                                        "harmless": stats.get("harmless", 0),
                                        "undetected": stats.get("undetected", 0),
                                        "total": sum(stats.values()) if stats else 0,
                                        "scan_date": attributes.get("date"),
                                        "file_hash": file_hash,
                                        "analysis_type": "new_upload"
                                    }
                                elif attributes.get("status") == "queued":
                                    continue  # 계속 대기
                                else:
                                    break  # 오류 또는 다른 상태

                        # 2분 대기 후에도 완료되지 않음
                        return {"error": "VirusTotal 분석이 시간 초과되었습니다. 나중에 다시 시도해주세요."}
                    else:
                        return {"error": "VirusTotal 업로드 실패: analysis_id를 받지 못했습니다"}
                else:
                    return {"error": f"VirusTotal 업로드 실패: HTTP {upload_response.status_code}"}

            else:
                return {"error": f"VirusTotal 조회 실패: HTTP {response.status_code}"}

        except Exception as e:
            return {"error": f"VirusTotal 검사 중 오류: {str(e)}"}

    def get_clean_samples(self, count: int = 20) -> List[str]:
        """정상 문서 샘플 생성 (균형잡힌 형식)"""
        clean_files = []
        os.makedirs("sample/clear", exist_ok=True)

        # 형식별 정상 샘플 생성 비율
        format_ratios = {
            'pdf': 0.3,  # 30%
            'docx': 0.25,  # 25%
            'xlsx': 0.2,  # 20%
            'pptx': 0.15,  # 15%
            'txt': 0.1  # 10%
        }

        try:
            # PDF 샘플 생성
            pdf_count = int(count * format_ratios['pdf'])
            if pdf_count > 0:
                try:
                    from reportlab.pdfgen import canvas
                    from reportlab.lib.pagesizes import letter

                    for i in range(pdf_count):
                        file_path = f"sample/clear/clean_pdf_{i:03d}.pdf"

                        c = canvas.Canvas(file_path, pagesize=letter)
                        c.drawString(100, 750, f"정상 PDF 문서 #{i + 1}")
                        c.drawString(100, 730, "이것은 안전한 정상 PDF 문서입니다.")
                        c.drawString(100, 710, f"생성일: {time.strftime('%Y-%m-%d %H:%M:%S')}")
                        c.drawString(100, 690, "내용: 일반적인 비즈니스 문서")
                        c.drawString(100, 670, "특징: JavaScript 없음, 안전한 구조")
                        c.save()

                        clean_files.append(file_path)

                except ImportError:
                    print("reportlab이 설치되지 않아 PDF 생성을 건너뜁니다.")

            # DOCX 샘플 생성 (간단한 텍스트 파일로 대체)
            docx_count = int(count * format_ratios['docx'])
            for i in range(docx_count):
                file_path = f"sample/clear/clean_docx_{i:03d}.txt"  # 실제로는 txt
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(f"정상 Word 문서 #{i + 1}\n")
                    f.write("이것은 안전한 정상 Word 문서입니다.\n")
                    f.write(f"생성일: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("내용: 일반적인 문서\n")
                    f.write("특징: 매크로 없음, 안전한 구조\n")
                clean_files.append(file_path)

            # XLSX 샘플 생성 (CSV로 대체)
            xlsx_count = int(count * format_ratios['xlsx'])
            for i in range(xlsx_count):
                file_path = f"sample/clear/clean_xlsx_{i:03d}.csv"
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("이름,나이,직업\n")
                    f.write("홍길동,30,개발자\n")
                    f.write("김철수,25,디자이너\n")
                    f.write("이영희,35,관리자\n")
                clean_files.append(file_path)

            # PPTX 샘플 생성 (텍스트 파일로 대체)
            pptx_count = int(count * format_ratios['pptx'])
            for i in range(pptx_count):
                file_path = f"sample/clear/clean_pptx_{i:03d}.txt"
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(f"정상 PowerPoint 프레젠테이션 #{i + 1}\n")
                    f.write("슬라이드 1: 제목\n")
                    f.write("슬라이드 2: 내용\n")
                    f.write("슬라이드 3: 결론\n")
                    f.write("특징: 매크로 없음, 안전한 구조\n")
                clean_files.append(file_path)

            # 나머지는 일반 텍스트 파일
            remaining = count - len(clean_files)
            for i in range(remaining):
                file_path = f"sample/clear/clean_text_{i:03d}.txt"
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(f"정상 텍스트 문서 #{i + 1}\n")
                    f.write("이것은 안전한 정상 문서입니다.\n")
                    f.write(f"생성일: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("내용: 일반적인 텍스트 문서\n")
                clean_files.append(file_path)

        except Exception as e:
            print(f"정상 샘플 생성 중 오류: {e}")

        return clean_files


# 기존 클래스와의 호환성을 위한 별칭
APIClient = BalancedAPIClient


def collect_training_data_balanced(malware_count: int = 300, clean_count: int = 300):
    """균형잡힌 훈련 데이터 수집"""
    client = BalancedAPIClient()

    print("🚀 균형잡힌 훈련 데이터 수집 시작")
    print("=" * 60)
    print(f"목표: 악성 {malware_count}개 + 정상 {clean_count}개")
    print("")

    # 악성 샘플 균형잡힌 수집
    print("📋 악성 샘플 균형잡힌 수집 중...")
    malware_files = client.download_malware_samples_balanced(malware_count)

    # 정상 샘플 생성
    print(f"\n📄 정상 샘플 {clean_count}개 생성 중...")
    clean_files = client.get_clean_samples(clean_count)
    print(f"✅ 정상 샘플 생성 완료: {len(clean_files)}개")

    # 최종 결과
    total_samples = len(malware_files) + len(clean_files)
    print(f"\n🎯 최종 수집 결과:")
    print(f"   악성 샘플: {len(malware_files)}개")
    print(f"   정상 샘플: {len(clean_files)}개")
    print(f"   총 샘플: {total_samples}개")

    target_total = malware_count + clean_count
    success_rate = (total_samples / target_total) * 100 if target_total > 0 else 0
    print(f"   달성률: {success_rate:.1f}%")

    # 형식별 분포 출력
    print(f"\n📊 악성 샘플 형식별 분포:")
    for file_format, count in client.download_stats['format_distribution'].items():
        if count > 0:
            print(f"   {file_format.upper()}: {count}개")

    return malware_files, clean_files


# 기존 함수와의 호환성
def collect_training_data(malware_count: int = 15, clean_count: int = 15):
    """기존 호환성 유지"""
    return collect_training_data_balanced(malware_count, clean_count)


if __name__ == "__main__":
    # 테스트
    client = BalancedAPIClient()

    print("=== 균형잡힌 API 클라이언트 테스트 ===")
    print(f"MalwareBazaar 연결: {'✓' if client.test_malware_bazaar_connection() else '✗'}")
    print(f"VirusTotal 연결: {'✓' if client.test_virustotal_connection() else '✗'}")
    print(f"Tria.ge 연결: {'✓' if client.test_triage_connection() else '✗ (선택사항)'}")

    # 소규모 균형 테스트
    print(f"\n=== 소규모 균형 테스트 (30개) ===")
    test_files = client.download_malware_samples_balanced(30)
    print(f"테스트 결과: {len(test_files)}개 다운로드")

    print(f"\n파일 형식별 분포:")
    for file_format, count in client.download_stats['format_distribution'].items():
        if count > 0:
            print(f"  {file_format.upper()}: {count}개")