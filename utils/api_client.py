import requests
import os
import time
import hashlib
from typing import List, Dict, Optional
from dotenv import load_dotenv

load_dotenv()


class APIClient:
    def __init__(self):
        self.malware_bazaar_key = os.getenv('MALWARE_BAZAAR_API_KEY')
        self.triage_key = os.getenv('TRIAGE_API_KEY')
        self.session = requests.Session()

        # 수집 대상 문서 타입 정의
        self.document_types = {
            'pdf': {'extensions': ['.pdf'], 'target': 60, 'priority': 'high'},
            'word': {'extensions': ['.doc', '.docx'], 'target': 60, 'priority': 'high'},
            'excel': {'extensions': ['.xls', '.xlsx'], 'target': 50, 'priority': 'medium'},
            'powerpoint': {'extensions': ['.ppt', '.pptx'], 'target': 40, 'priority': 'medium'},
            'hwp': {'extensions': ['.hwp', '.hwpx', '.hwpml'], 'target': 40, 'priority': 'high'},
            'rtf': {'extensions': ['.rtf'], 'target': 30, 'priority': 'low'},
            'other': {'extensions': [], 'target': 20, 'priority': 'low'}
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

    def test_triage_connection(self) -> bool:
        """Triage API 연결 테스트"""
        try:
            if not self.triage_key:
                return False

            headers = {"Authorization": f"Bearer {self.triage_key}"}
            url = "https://api.tria.ge/v0/samples"
            response = self.session.get(url, headers=headers, timeout=10)
            return response.status_code in [200, 401]
        except Exception as e:
            print(f"Triage 연결 실패: {e}")
            return False

    def download_malware_samples(self, count: int = 300) -> List[str]:
        """다중 소스에서 대량 악성코드 샘플 수집"""
        downloaded_files = []

        print(f"=== 대량 샘플 수집 시작 (목표: {count}개) ===")

        # MalwareBazaar에서 60% 수집
        mb_target = int(count * 0.6)
        mb_files = self._collect_from_malware_bazaar(mb_target)
        downloaded_files.extend(mb_files)
        print(f"MalwareBazaar 수집 완료: {len(mb_files)}개")

        # Triage에서 40% 수집
        triage_target = count - len(downloaded_files)
        if triage_target > 0 and self.triage_key:
            triage_files = self._collect_from_triage(triage_target)
            downloaded_files.extend(triage_files)
            print(f"Triage 수집 완료: {len(triage_files)}개")

        print(f"총 수집 완료: {len(downloaded_files)}개")
        return downloaded_files

    def _collect_from_malware_bazaar(self, target_count: int) -> List[str]:
        """MalwareBazaar에서 문서 악성코드 수집"""
        if not self.malware_bazaar_key:
            return []

        downloaded_files = []
        url = "https://mb-api.abuse.ch/api/v1/"
        headers = {"Auth-Key": self.malware_bazaar_key}

        # 확장된 검색 전략
        search_strategies = [
            {"query": "get_recent", "selector": "3000"},
            {"query": "get_taginfo", "tag": "pdf", "limit": "300"},
            {"query": "get_taginfo", "tag": "doc", "limit": "300"},
            {"query": "get_taginfo", "tag": "docx", "limit": "300"},
            {"query": "get_taginfo", "tag": "xls", "limit": "300"},
            {"query": "get_taginfo", "tag": "xlsx", "limit": "300"},
            {"query": "get_taginfo", "tag": "ppt", "limit": "200"},
            {"query": "get_taginfo", "tag": "pptx", "limit": "200"},
            {"query": "get_taginfo", "tag": "hwp", "limit": "300"},
            {"query": "get_taginfo", "tag": "rtf", "limit": "200"},
            {"query": "get_taginfo", "tag": "emotet", "limit": "200"},
            {"query": "get_taginfo", "tag": "trickbot", "limit": "200"},
            {"query": "get_taginfo", "tag": "qakbot", "limit": "200"},
            {"query": "get_taginfo", "tag": "office", "limit": "300"},
            {"query": "get_taginfo", "tag": "macro", "limit": "300"},
        ]

        all_samples = []
        existing_hashes = set()

        for strategy in search_strategies:
            try:
                response = self.session.post(url, data=strategy, headers=headers, timeout=30)

                if response.status_code == 200:
                    result = response.json()
                    if result.get("query_status") == "ok":
                        samples = result.get("data", [])

                        for sample in samples:
                            hash_val = sample.get("sha256_hash")
                            if hash_val and hash_val not in existing_hashes:
                                all_samples.append(sample)
                                existing_hashes.add(hash_val)

                time.sleep(0.5)

            except Exception as e:
                print(f"MalwareBazaar 검색 오류: {e}")
                continue

        # 문서 타입별 분류 및 선택
        categorized = self._categorize_samples(all_samples)
        selected = self._select_balanced_samples(categorized, target_count)

        # 다운로드 실행
        os.makedirs("sample/mecro", exist_ok=True)

        for i, sample in enumerate(selected):
            if len(downloaded_files) >= target_count:
                break

            try:
                file_path = self._download_mb_sample(sample, i, url, headers)
                if file_path:
                    downloaded_files.append(file_path)

                time.sleep(1.5)

            except Exception as e:
                print(f"MalwareBazaar 다운로드 오류: {e}")
                continue

        return downloaded_files

    def _collect_from_triage(self, target_count: int) -> List[str]:
        """Triage에서 다양한 문서 악성코드 수집"""
        if not self.triage_key:
            return []

        downloaded_files = []
        headers = {"Authorization": f"Bearer {self.triage_key}"}

        # Triage 검색 쿼리
        search_queries = [
            "tag:pdf", "tag:doc OR tag:docx", "tag:xls OR tag:xlsx",
            "tag:ppt OR tag:pptx", "tag:hwp", "tag:rtf",
            "family:emotet", "family:trickbot", "family:qakbot",
            "family:formbook", "family:agent_tesla", "family:lokibot",
            "tag:office", "tag:macro", "tag:document", "country:kr"
        ]

        all_samples = []

        for query in search_queries:
            try:
                url = f"https://api.tria.ge/v0/search?query={query}&limit=100"
                response = self.session.get(url, headers=headers, timeout=30)

                if response.status_code == 200:
                    result = response.json()
                    samples = result.get("data", [])
                    all_samples.extend(samples)
                    print(f"Triage '{query}': {len(samples)}개 발견")

                time.sleep(1)

            except Exception as e:
                print(f"Triage 검색 오류 '{query}': {e}")
                continue

        # 중복 제거
        unique_samples = []
        seen_ids = set()
        for sample in all_samples:
            sample_id = sample.get("id")
            if sample_id and sample_id not in seen_ids:
                unique_samples.append(sample)
                seen_ids.add(sample_id)

        print(f"Triage 총 고유 샘플: {len(unique_samples)}개")

        # 다운로드 실행
        for i, sample in enumerate(unique_samples[:target_count]):
            if len(downloaded_files) >= target_count:
                break

            try:
                file_path = self._download_triage_sample(sample, i, headers)
                if file_path:
                    downloaded_files.append(file_path)

                time.sleep(2)

            except Exception as e:
                print(f"Triage 다운로드 오류: {e}")
                continue

        return downloaded_files

    def _categorize_samples(self, samples: List[Dict]) -> Dict[str, List]:
        """샘플을 문서 타입별로 분류"""
        categorized = {doc_type: [] for doc_type in self.document_types.keys()}

        for sample in samples:
            file_name = (sample.get("file_name") or "").lower()
            file_type = (sample.get("file_type") or "").lower()
            mime_type = (sample.get("file_type_mime") or "").lower()

            classified = False

            for doc_type, config in self.document_types.items():
                if doc_type == 'other':
                    continue

                extensions = config['extensions']
                for ext in extensions:
                    if ext in file_name or ext.replace('.', '') in file_type or ext.replace('.', '') in mime_type:
                        categorized[doc_type].append(sample)
                        classified = True
                        break

                if classified:
                    break

            if not classified:
                categorized['other'].append(sample)

        return categorized

    def _select_balanced_samples(self, categorized: Dict[str, List], target_count: int) -> List:
        """타입별 균등 선택"""
        selected = []

        # 우선순위별로 선택
        for doc_type, samples in categorized.items():
            target = min(self.document_types[doc_type]['target'], len(samples))
            selected.extend(samples[:target])

        # 부족하면 추가 선택
        if len(selected) < target_count:
            remaining = target_count - len(selected)
            all_remaining = []
            for doc_type, samples in categorized.items():
                target = self.document_types[doc_type]['target']
                all_remaining.extend(samples[target:])
            selected.extend(all_remaining[:remaining])

        return selected[:target_count]

    def _download_mb_sample(self, sample: Dict, index: int, url: str, headers: Dict) -> Optional[str]:
        """MalwareBazaar 샘플 다운로드"""
        try:
            sha256_hash = sample.get("sha256_hash")
            file_name = sample.get("file_name") or f"mb_malware_{index:03d}"

            if not sha256_hash:
                return None

            safe_filename = "".join(c for c in str(file_name) if c.isalnum() or c in '._-')[:50]
            if not safe_filename:
                safe_filename = f"mb_malware_{index:03d}"

            download_data = {"query": "get_file", "sha256_hash": sha256_hash}
            response = self.session.post(url, data=download_data, headers=headers, timeout=60)

            if response.status_code == 200 and response.content:
                zip_path = os.path.join("sample/mecro", f"{safe_filename}.zip")

                with open(zip_path, "wb") as f:
                    f.write(response.content)

                extracted_path = self._extract_zip(zip_path, safe_filename)
                return extracted_path if extracted_path else zip_path

        except Exception as e:
            print(f"MalwareBazaar 샘플 다운로드 실패: {e}")

        return None

    def _download_triage_sample(self, sample: Dict, index: int, headers: Dict) -> Optional[str]:
        """Triage 샘플 다운로드"""
        try:
            sample_id = sample.get("id")
            if not sample_id:
                return None

            # 샘플 상세 정보 조회
            detail_url = f"https://api.tria.ge/v0/samples/{sample_id}"
            detail_response = self.session.get(detail_url, headers=headers, timeout=30)

            if detail_response.status_code != 200:
                return None

            detail = detail_response.json()
            filename = detail.get("filename", f"triage_sample_{index:03d}")

            # 파일 다운로드
            download_url = f"https://api.tria.ge/v0/samples/{sample_id}/sample"
            download_response = self.session.get(download_url, headers=headers, timeout=60)

            if download_response.status_code == 200:
                safe_filename = "".join(c for c in filename if c.isalnum() or c in '._-')[:50]
                if not safe_filename:
                    safe_filename = f"triage_sample_{index:03d}"

                file_path = os.path.join("sample/mecro", safe_filename)

                with open(file_path, "wb") as f:
                    f.write(download_response.content)

                return file_path

        except Exception as e:
            print(f"Triage 샘플 다운로드 실패: {e}")

        return None

    def _extract_zip(self, zip_path: str, filename: str) -> Optional[str]:
        """ZIP 파일 압축 해제"""
        try:
            import pyzipper

            with pyzipper.AESZipFile(zip_path, 'r') as zip_ref:
                zip_ref.pwd = b'infected'
                extracted_files = zip_ref.namelist()

                if extracted_files:
                    zip_ref.extractall("sample/mecro")

                    old_path = os.path.join("sample/mecro", extracted_files[0])
                    new_path = os.path.join("sample/mecro", filename)

                    if os.path.exists(old_path):
                        if os.path.exists(new_path):
                            os.remove(new_path)
                        os.rename(old_path, new_path)
                        os.remove(zip_path)
                        return new_path
        except:
            try:
                import zipfile
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.setpassword(b'infected')
                    extracted_files = zip_ref.namelist()

                    if extracted_files:
                        zip_ref.extractall("sample/mecro")
                        old_path = os.path.join("sample/mecro", extracted_files[0])
                        new_path = os.path.join("sample/mecro", filename)

                        if os.path.exists(old_path):
                            if os.path.exists(new_path):
                                os.remove(new_path)
                            os.rename(old_path, new_path)
                            os.remove(zip_path)
                            return new_path
            except:
                pass

        return None

    def get_clean_samples(self, count: int = 300) -> List[str]:
        """대량 정상 문서 샘플 생성"""
        clean_files = []
        os.makedirs("sample/clear", exist_ok=True)

        try:
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import letter

            # 다양한 타입의 정상 문서 생성
            pdf_count = count // 3
            text_count = count // 3
            simple_count = count - pdf_count - text_count

            # PDF 샘플
            for i in range(pdf_count):
                file_path = f"sample/clear/clean_document_{i:03d}.pdf"

                c = canvas.Canvas(file_path, pagesize=letter)
                c.drawString(100, 750, f"Clean Business Document #{i + 1}")
                c.drawString(100, 730, "This is a legitimate business document.")
                c.drawString(100, 710, f"Generated: {time.strftime('%Y-%m-%d')}")
                c.drawString(100, 690, "Content: Normal business operations report.")
                c.save()

                clean_files.append(file_path)

            # 텍스트 샘플
            for i in range(text_count):
                file_path = f"sample/clear/clean_text_{i:03d}.txt"

                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(f"Clean Text Document #{i + 1}\n")
                    f.write("This is a normal business document.\n")
                    f.write(f"Created: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("This document contains no malicious content.\n")

                clean_files.append(file_path)

            # 추가 간단 샘플
            for i in range(simple_count):
                file_path = f"sample/clear/simple_clean_{i:03d}.txt"

                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(f"Simple Clean Document #{i + 1}\n")
                    f.write("Safe content for training.\n")

                clean_files.append(file_path)

        except ImportError:
            # reportlab 없으면 모두 텍스트로
            for i in range(count):
                file_path = f"sample/clear/clean_document_{i:03d}.txt"

                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(f"Clean Document #{i + 1}\n")
                    f.write("Safe document content.\n")
                    f.write(f"Generated: {time.strftime('%Y-%m-%d')}\n")

                clean_files.append(file_path)

        return clean_files

    def check_file_with_triage(self, file_path: str) -> Dict:
        """Triage로 파일 검사"""
        if not self.triage_key:
            return {"error": "Triage API 키가 없습니다"}

        try:
            headers = {"Authorization": f"Bearer {self.triage_key}"}

            # 파일 해시 계산
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            # Triage에서 결과 조회
            url = f"https://api.tria.ge/v0/samples/{file_hash}"
            response = self.session.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                result = response.json()
                return {
                    "status": "found",
                    "analysis": result
                }
            else:
                return {"status": "not_found"}

        except Exception as e:
            return {"error": f"Triage 검사 오류: {str(e)}"}


# 수집 함수들
def collect_training_data(malware_count: int = 300, clean_count: int = 300):
    """대량 훈련 데이터 수집 (다중 소스 활용)"""
    client = APIClient()

    print("=== 대량 훈련 데이터 수집 시작 ===")
    print(f"목표: 악성 {malware_count}개 + 정상 {clean_count}개")

    # 악성 샘플 다운로드
    print(f"\n악성 샘플 수집 중...")
    malware_files = client.download_malware_samples(malware_count)
    print(f"악성 샘플 수집 완료: {len(malware_files)}개")

    # 정상 샘플 생성
    print(f"\n정상 샘플 생성 중...")
    clean_files = client.get_clean_samples(clean_count)
    print(f"정상 샘플 생성 완료: {len(clean_files)}개")

    # 수집 결과 요약
    print(f"\n=== 수집 완료 ===")
    print(f"총 수집: {len(malware_files) + len(clean_files)}개")
    print(f"  - 악성: {len(malware_files)}개")
    print(f"  - 정상: {len(clean_files)}개")

    return malware_files, clean_files


def collect_additional_training_data(target_count: int = 100):
    """추가 훈련 데이터 수집 (모델 업데이트용)"""
    client = APIClient()

    print(f"=== 추가 샘플 수집 (목표: {target_count}개) ===")

    # 새로운 악성 샘플 수집
    new_malware = client.download_malware_samples(target_count)
    print(f"새로운 악성 샘플: {len(new_malware)}개 수집 완료")

    return len(new_malware)


if __name__ == "__main__":
    # 기본 대량 수집 실행
    collect_training_data(300, 300)