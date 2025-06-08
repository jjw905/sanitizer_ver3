# utils/api_client.py - 가상 파일 생성 기능 제거 후 최종 버전

import os
import requests
import time
import hashlib
import json
from typing import List, Tuple
from dotenv import load_dotenv
import config
from utils import db, aws_helper

load_dotenv()


class APIClient:
    def __init__(self):
        self.malware_bazaar_key = os.getenv('MALWARE_BAZAAR_API_KEY')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.triage_key = os.getenv('TRIAGE_API_KEY')

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DocSanitizer/2.2'
        })

    def test_malware_bazaar_connection(self) -> bool:
        """MalwareBazaar API 연결 테스트"""
        if not self.malware_bazaar_key:
            return False

        try:
            data = {
                'query': 'get_info',
                'api_key': self.malware_bazaar_key
            }
            response = requests.post(
                'https://mb-api.abuse.ch/api/v1/',
                data=data,
                timeout=10
            )
            return response.status_code == 200
        except:
            return False

    def test_virustotal_connection(self) -> bool:
        """VirusTotal API 연결 테스트"""
        if not self.virustotal_key:
            return False

        try:
            headers = {'x-apikey': self.virustotal_key}
            response = requests.get(
                'https://www.virustotal.com/api/v3/users/current',
                headers=headers,
                timeout=10
            )
            return response.status_code == 200
        except:
            return False

    def test_triage_connection(self) -> bool:
        """Tria.ge API 연결 테스트"""
        if not self.triage_key:
            return False

        try:
            headers = {'Authorization': f'Bearer {self.triage_key}'}
            response = requests.get(
                'https://api.tria.ge/v0/samples',
                headers=headers,
                params={'limit': 1},
                timeout=10
            )
            return response.status_code == 200
        except:
            return False

    def collect_malware_samples_malware_bazaar(self, count: int = 150) -> List[str]:
        """MalwareBazaar에서 악성 샘플 수집 (키워드 최적화)"""
        if not self.malware_bazaar_key:
            print("[MB] API 키가 없습니다")
            return []

        collected_files = []

        # 문서형 악성코드 특징, 행위, 취약점 기반 태그로 최적화
        document_tags = [
            'emotet', 'trickbot', 'qakbot', 'dridex', 'ursnif', 'formbook',
            'agent-tesla', 'lokibot', 'icedid',
            'macro', 'vba', 'dropper', 'downloader', 'phishing', 'spearphishing',
            'infostealer', 'keylogger',
            'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'pdf',
            'office', 'document', 'rtf',
            'invoice', 'payment', 'order', 'receipt', 'resume',
            'cve-2017-11882', 'cve-2018-0802', 'follina'
        ]

        for tag in document_tags:
            if len(collected_files) >= count:
                break

            print(f"[MB] {tag} 태그 샘플 수집 중...")

            try:
                data = {
                    'query': 'get_taginfo',
                    'tag': tag,
                    'limit': 20,
                    'api_key': self.malware_bazaar_key
                }

                response = requests.post(
                    'https://mb-api.abuse.ch/api/v1/',
                    data=data,
                    timeout=30
                )

                if response.status_code == 200:
                    result = response.json()
                    samples = result.get('data', [])

                    for sample in samples:
                        if len(collected_files) >= count:
                            break

                        file_name = sample.get('file_name', '')
                        file_ext = os.path.splitext(file_name)[1].lower()

                        if file_ext in ['.doc', '.docx', '.docm', '.pdf', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx',
                                        '.pptm', '.hwp']:
                            download_url = sample.get('urlhaus_download')
                            sha256_hash = sample.get('sha256')

                            if download_url and sha256_hash:
                                file_path = self._download_sample(download_url, sha256_hash, file_ext)
                                if file_path:
                                    collected_files.append(file_path)
                                    self._save_sample_metadata(
                                        file_path, sha256_hash, True, 'malware_bazaar',
                                        sample.get('signature'), 'malware'
                                    )
                time.sleep(1)
            except Exception as e:
                print(f"[MB] {tag} 수집 오류: {e}")
                continue

        print(f"[MB] 총 {len(collected_files)}개 악성 샘플 수집 완료")
        return collected_files

    def collect_malware_samples_triage(self, count: int = 100) -> List[str]:
        """Tria.ge에서 악성 샘플 수집 (쿼리 최적화)"""
        if not self.triage_key:
            print("[Triage] API 키가 없습니다")
            return []

        collected_files = []
        headers = {'Authorization': f'Bearer {self.triage_key}'}

        queries = [
            'kind:document AND family:emotet',
            'kind:document AND family:trickbot',
            'kind:document AND family:qakbot',
            'kind:document AND family:dridex',
            'kind:document AND family:icedid',
            'kind:document AND (family:formbook OR family:agent-tesla OR family:lokibot)',
            'tag:macro AND kind:document AND family:ursnif',
            'tag:phishing AND (ext:docx OR ext:pdf OR ext:xlsx)',
            'tag:invoice AND kind:document',
            'tag:cve-2017-11882 AND kind:document',
            'ext:pdf AND (tag:js OR tag:javascript)',
            'ext:docm',
            'ext:xlsm'
        ]

        for query in queries:
            if len(collected_files) >= count:
                break

            print(f"[Triage] 쿼리 실행: {query}")

            try:
                params = {
                    'query': query,
                    'limit': 15,
                    'subset': 'public'
                }

                response = requests.get(
                    'https://api.tria.ge/v0/search',
                    headers=headers,
                    params=params,
                    timeout=30
                )

                if response.status_code == 200:
                    result = response.json()
                    samples = result.get('data', [])

                    for sample in samples:
                        if len(collected_files) >= count:
                            break

                        sample_id = sample.get('id')
                        filename = sample.get('filename', '')
                        file_ext = os.path.splitext(filename)[1].lower()

                        if file_ext in ['.doc', '.docx', '.docm', '.pdf', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx',
                                        '.pptm', '.hwp']:
                            file_path = self._download_triage_sample(sample_id, filename)
                            if file_path:
                                collected_files.append(file_path)
                                with open(file_path, 'rb') as f:
                                    file_hash = hashlib.sha256(f.read()).hexdigest()
                                self._save_sample_metadata(
                                    file_path, file_hash, True, 'triage',
                                    sample.get('family'), 'malware'
                                )
                time.sleep(2)
            except Exception as e:
                print(f"[Triage] 쿼리 오류: {e}")
                continue

        print(f"[Triage] 총 {len(collected_files)}개 악성 샘플 수집 완료")
        return collected_files

    # <<< 변경된 부분 시작 >>>
    # 가상 클린 파일 생성 관련 함수들을 모두 제거하고, 아래 함수로 대체합니다.
    # _create_verified_clean_sample, _generate_minimal_clean_samples 및
    # XML 생성 헬퍼 함수들 (_get_content_types_xml 등)은 모두 삭제되었습니다.

    def collect_clean_samples_verified(self, count: int = 80) -> List[str]:
        """
        정상 샘플 수집 함수 (가상 파일 생성 기능 제거)
        이제 이 함수는 자동 수집을 수행하지 않습니다.
        정상 샘플은 import_clean_files.py 스크립트를 통해 수동으로 검증 및 추가해야 합니다.
        """
        print("[Clean] 자동 정상 샘플 수집 기능이 비활성화되었습니다.")
        print("[Clean] 'import_clean_files.py'를 사용하여 '진짜' 정상 파일을 수동으로 추가해주세요.")

        # 기존 로컬 파일이 있다면 그것을 사용하고, 없다면 빈 리스트를 반환합니다.
        local_clean_dir = config.DIRECTORIES.get('clean_samples')
        if os.path.exists(local_clean_dir):
            existing_clean_files = [os.path.join(local_clean_dir, f) for f in os.listdir(local_clean_dir) if
                                    os.path.isfile(os.path.join(local_clean_dir, f))]
            print(f"[Clean] 기존에 수집된 로컬 정상 파일 {len(existing_clean_files)}개를 사용합니다.")
            return existing_clean_files[:count]  # 요청된 개수만큼만 반환

        return []

    # <<< 변경된 부분 끝 >>>

    def _download_sample(self, url: str, file_hash: str, file_ext: str) -> str:
        """샘플 파일 다운로드"""
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                os.makedirs(config.DIRECTORIES['malware_samples'], exist_ok=True)

                filename = f"{file_hash[:16]}{file_ext}"
                file_path = os.path.join(config.DIRECTORIES['malware_samples'], filename)

                with open(file_path, 'wb') as f:
                    f.write(response.content)

                return file_path
        except Exception as e:
            print(f"다운로드 실패 {url}: {e}")

        return None

    def _download_triage_sample(self, sample_id: str, filename: str) -> str:
        """Tria.ge 샘플 다운로드"""
        try:
            headers = {'Authorization': f'Bearer {self.triage_key}'}

            response = requests.get(
                f'https://api.tria.ge/v0/samples/{sample_id}/sample',
                headers=headers,
                timeout=60
            )

            if response.status_code == 200:
                os.makedirs(config.DIRECTORIES['malware_samples'], exist_ok=True)

                safe_filename = f"triage_{sample_id}_{filename.replace('/', '_')}"
                file_path = os.path.join(config.DIRECTORIES['malware_samples'], safe_filename)

                with open(file_path, 'wb') as f:
                    f.write(response.content)

                return file_path

        except Exception as e:
            print(f"Triage 다운로드 실패 {sample_id}: {e}")

        return None

    def _save_sample_metadata(self, file_path: str, file_hash: str, is_malicious: bool,
                              source: str, malware_family: str = None, threat_category: str = None):
        """샘플 메타데이터를 RDS에 저장"""
        try:
            s3_key = None
            if config.USE_AWS:
                s3_key = aws_helper.upload_virus_sample(file_path, file_hash)

            db.save_virus_sample(
                file_path=file_path,
                file_hash=file_hash,
                is_malicious=is_malicious,
                source=source,
                malware_family=malware_family,
                threat_category=threat_category,
                s3_key=s3_key
            )

        except Exception as e:
            print(f"메타데이터 저장 실패: {e}")

    def check_file_with_virustotal(self, file_path: str) -> dict:
        """VirusTotal로 파일 검사"""
        if not self.virustotal_key:
            return {"error": "VirusTotal API 키가 설정되지 않음"}

        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            headers = {'x-apikey': self.virustotal_key}
            response = requests.get(
                f'https://www.virustotal.com/api/v3/files/{file_hash}',
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})

                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'total': sum(stats.values()) if stats else 0,
                    'scan_date': attributes.get('last_analysis_date'),
                    'clean': stats.get('harmless', 0) + stats.get('undetected', 0)
                }
            elif response.status_code == 404:
                return {"error": "파일이 VirusTotal 데이터베이스에 없음"}
            else:
                return {"error": f"VirusTotal API 오류: {response.status_code}"}

        except Exception as e:
            return {"error": f"VirusTotal 검사 오류: {str(e)}"}


def collect_training_data_with_progress(malware_count: int = 200, clean_count: int = 100,
                                        progress_callback=None) -> Tuple[List[str], List[str]]:
    """훈련 데이터 수집 (정상 샘플은 수동 추가 방식 권장)"""

    def progress(msg):
        if progress_callback:
            progress_callback(msg)
        else:
            print(f"[수집] {msg}")

    client = APIClient()

    progress("API 연결 상태 확인 중...")

    mb_available = client.test_malware_bazaar_connection()
    triage_available = client.test_triage_connection()

    progress(f"MalwareBazaar: {'사용 가능' if mb_available else '사용 불가'}")
    progress(f"Tria.ge: {'사용 가능' if triage_available else '사용 불가'}")

    malware_files = []

    # 악성 샘플 수집
    if mb_available:
        progress("MalwareBazaar에서 악성 샘플 수집 중...")
        mb_files = client.collect_malware_samples_malware_bazaar(malware_count * 60 // 100)
        malware_files.extend(mb_files)

    if triage_available:
        progress("Tria.ge에서 악성 샘플 수집 중...")
        remaining_malware = malware_count - len(malware_files)
        if remaining_malware > 0:
            triage_files = client.collect_malware_samples_triage(remaining_malware)
            malware_files.extend(triage_files)

    # 정상 샘플은 기존 로컬 파일만 사용
    progress("로컬 정상 샘플 확인 중...")
    clean_files = client.collect_clean_samples_verified(clean_count)

    progress("중복 파일 제거 중...")
    malware_files = remove_duplicates(malware_files)
    clean_files = remove_duplicates(clean_files)

    # 비율 조정
    if len(clean_files) > len(malware_files) * 0.7:
        clean_files = clean_files[:int(len(malware_files) * 0.7)]
        progress(f"정상 샘플 수를 {len(clean_files)}개로 조정 (악성 대비 70% 이하)")

    progress(f"수집 완료: 악성 {len(malware_files)}개, 정상 {len(clean_files)}개")
    if (len(malware_files) + len(clean_files)) > 0:
        progress(
            f"비율: 악성 {len(malware_files) / (len(malware_files) + len(clean_files)) * 100:.1f}%, 정상 {len(clean_files) / (len(malware_files) + len(clean_files)) * 100:.1f}%")

    return malware_files, clean_files


def remove_duplicates(file_paths: List[str]) -> List[str]:
    """파일 해시 기반 중복 제거"""
    unique_files = []
    seen_hashes = set()

    for file_path in file_paths:
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            if file_hash not in seen_hashes:
                unique_files.append(file_path)
                seen_hashes.add(file_hash)
            else:
                try:
                    os.remove(file_path)
                except:
                    pass
        except Exception as e:
            print(f"해시 계산 실패 {file_path}: {e}")

    return unique_files


if __name__ == "__main__":
    client = APIClient()

    print("=== API 연결 테스트 ===")
    print(f"MalwareBazaar: {client.test_malware_bazaar_connection()}")
    print(f"VirusTotal: {client.test_virustotal_connection()}")
    print(f"Tria.ge: {client.test_triage_connection()}")

    print("\n=== 샘플 수집 테스트 ===")
    malware_files, clean_files = collect_training_data_with_progress(50, 30)
    print(f"결과: 악성 {len(malware_files)}개, 정상 {len(clean_files)}개")