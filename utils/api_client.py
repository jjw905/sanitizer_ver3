# utils/api_client.py - 최종 버전

import os
import requests
import time
import hashlib
import json
from typing import List, Tuple
from dotenv import load_dotenv

# 다른 로컬 모듈을 임포트하기 위해 경로 설정
try:
    import config
    from utils import db, aws_helper
except ImportError:
    # 상위 디렉토리의 모듈을 찾기 위해 경로 추가
    import sys

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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
        if not self.malware_bazaar_key: return False
        try:
            headers = {'Auth-Key': self.malware_bazaar_key}
            data = {'query': 'get_info', 'hash': '094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d'}
            response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, headers=headers, timeout=10)
            return response.json().get('query_status') != 'no_api_key'
        except:
            return False

    def test_virustotal_connection(self) -> bool:
        if not self.virustotal_key: return False
        try:
            headers = {'x-apikey': self.virustotal_key}
            response = requests.get('https://www.virustotal.com/api/v3/users/current', headers=headers, timeout=10)
            return response.status_code == 200
        except:
            return False

    def test_triage_connection(self) -> bool:
        if not self.triage_key: return False
        try:
            headers = {'Authorization': f'Bearer {self.triage_key}'}
            response = requests.get('https://api.tria.ge/v0/samples', headers=headers, params={'limit': 1}, timeout=10)
            return response.status_code == 200
        except:
            return False

    def _download_sample(self, sha256_hash: str, file_ext: str) -> str:
        """MalwareBazaar 샘플 다운로드 (AES128 암호화 대응)"""
        if not self.malware_bazaar_key:
            return None

        import io
        import pyzipper
        import shutil

        try:
            headers = {'Auth-Key': self.malware_bazaar_key}
            data = {'query': 'get_file', 'sha256_hash': sha256_hash}

            print(f"  -> MB API로 다운로드 요청: {sha256_hash[:16]}...")
            response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, timeout=60, headers=headers)

            if response.status_code == 200:
                # 응답이 비어있는지 확인
                if not response.content:
                    print(f"  -> [오류] 응답 내용이 비어있음: {sha256_hash[:16]}...")
                    return None

                # 응답 크기 확인
                content_length = len(response.content)
                print(f"  -> 다운로드 크기: {content_length} bytes")

                if content_length < 100:  # 너무 작으면 오류 메시지일 가능성
                    print(f"  -> [오류] 파일 크기가 너무 작음")
                    return None

                # JSON 오류 응답인지 확인
                content_type = response.headers.get('Content-Type', '')
                if 'application/json' in content_type:
                    try:
                        json_response = response.json()
                        print(f"  -> [오류] API JSON 응답: {json_response}")
                        return None
                    except:
                        pass

                # ZIP 파일 처리 (AES 암호화 대응)
                zip_buffer = io.BytesIO(response.content)

                try:
                    # pyzipper로 AES 암호화된 ZIP 파일 처리
                    with pyzipper.AESZipFile(zip_buffer, 'r') as zip_ref:
                        # ZIP 파일 내용 확인
                        file_list = zip_ref.namelist()
                        if not file_list:
                            print(f"  -> [오류] ZIP 파일이 비어있음: {sha256_hash[:16]}...")
                            return None

                        print(f"  -> ZIP 파일 내용: {file_list}")

                        # 비밀번호로 압축 해제 시도
                        pwd = "infected"  # 문자열로 처리

                        for member_info in zip_ref.infolist():
                            if not member_info.is_dir():
                                output_dir = config.DIRECTORIES['malware_samples']
                                os.makedirs(output_dir, exist_ok=True)

                                final_filename = f"{sha256_hash}{file_ext}"
                                final_file_path = os.path.join(output_dir, final_filename)

                                # AES 암호화된 파일 추출
                                zip_ref.setpassword(pwd.encode('utf-8'))

                                with zip_ref.open(member_info) as source:
                                    with open(final_file_path, "wb") as target:
                                        shutil.copyfileobj(source, target)

                                print(f"  -> MB 다운로드 성공: {final_filename}")
                                return final_file_path

                except pyzipper.BadZipFile:
                    print(f"  -> [오류] 올바른 ZIP 파일이 아님: {sha256_hash[:16]}...")
                    print(f"     응답 시작 부분: {response.content[:100]}")
                    return None
                except pyzipper.LargeZipFile:
                    print(f"  -> [오류] ZIP 파일이 너무 큼: {sha256_hash[:16]}...")
                    return None
                except RuntimeError as e:
                    if "Bad password" in str(e) or "incorrect password" in str(e).lower():
                        print(f"  -> [오류] 비밀번호 오류 (AES 암호화): {sha256_hash[:16]}...")
                    else:
                        print(f"  -> [오류] AES ZIP 압축해제 실패: {e}")
                    return None
                except Exception as e:
                    print(f"  -> [오류] ZIP 처리 중 예외: {e}")
                    return None

                print(f"  -> [경고] ZIP 파일에 추출 가능한 파일이 없음: {sha256_hash[:16]}...")
                return None

            else:
                print(f"  -> [오류] 다운로드 실패 (HTTP {response.status_code})")
                try:
                    error_response = response.json()
                    print(f"     API 오류: {error_response}")
                except:
                    print(f"     응답 텍스트: {response.text[:200]}")
                return None

        except requests.exceptions.Timeout:
            print(f"  -> [오류] 다운로드 타임아웃: {sha256_hash[:16]}...")
            return None
        except requests.exceptions.RequestException as e:
            print(f"  -> [오류] 네트워크 오류: {e}")
            return None
        except Exception as e:
            print(f"  -> [오류] 알 수 없는 오류: {e}")
            return None

    def collect_malware_samples_malware_bazaar(self, count: int = 150) -> List[str]:
        """MalwareBazaar에서 악성 샘플 수집 (API 다운로드 방식 적용)"""
        if not self.malware_bazaar_key:
            print("[MB] API 키가 없습니다")
            return []
        collected_files = []
        document_tags = [
            'maldoc', 'downloader', 'dropper', 'macro', 'vba', 'phishing',
            'infostealer', 'doc', 'docx', 'pdf', 'xls', 'xlsx', 'rtf'
        ]
        headers = {'Auth-Key': self.malware_bazaar_key}
        for tag in document_tags:
            if len(collected_files) >= count: break
            print(f"[MB] '{tag}' 태그 샘플 수집 중...")
            try:
                data = {'query': 'get_taginfo', 'tag': tag, 'limit': 100}
                response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, headers=headers, timeout=30)
                if response.status_code == 200 and response.json().get('query_status') == 'ok':
                    samples = response.json().get('data', [])
                    for sample in samples:
                        if len(collected_files) >= count: break
                        sha256_hash = sample.get('sha256_hash')
                        file_type = sample.get('file_type')
                        if sha256_hash and 'document' in sample.get('file_type_mime', ''):
                            file_ext = f".{file_type}" if file_type else ".bin"
                            file_path = self._download_sample(sha256_hash, file_ext)
                            if file_path:
                                collected_files.append(file_path)
                                self._save_sample_metadata(
                                    file_path, sha256_hash, True, 'malware_bazaar',
                                    sample.get('signature'), 'malware'
                                )
                time.sleep(5)
            except Exception as e:
                print(f"[MB] '{tag}' 태그 수집 중 오류: {e}")
                time.sleep(15)
                continue
        print(f"[MB] 총 {len(collected_files)}개 악성 샘플 수집 완료")
        return collected_files

    def collect_malware_samples_triage(self, count: int = 100) -> List[str]:
        """Tria.ge에서 악성 샘플 수집 (수정된 단순 쿼리 적용)"""
        if not self.triage_key:
            print("[Triage] API 키가 없습니다")
            return []
        collected_files, headers = [], {'Authorization': f'Bearer {self.triage_key}'}

        from datetime import datetime, timedelta
        one_year_ago = (datetime.now() - timedelta(days=365)).strftime('%Y-%m-%d')
        date_filter = f"from:{one_year_ago}"

        queries = [
            f"tag:maldoc {date_filter}",
            f"tag:downloader ext:docx {date_filter}",
            f"tag:dropper ext:pdf {date_filter}",
            f"tag:exploit ext:pdf {date_filter}",
            f"tag:infostealer ext:xlsx {date_filter}",
            f"tag:rat ext:docm {date_filter}",
            f"tag:banker kind:document {date_filter}",
        ]

        for query in queries:
            if len(collected_files) >= count: break
            print(f"[Triage] 쿼리 실행: {query}")
            try:
                params = {'query': query, 'limit': 50, 'subset': 'public'}
                response = requests.get('https://api.tria.ge/v0/search', headers=headers, params=params, timeout=30)
                if response.status_code == 200:
                    samples = response.json().get('data', [])
                    if not samples:
                        print("  -> 반환된 샘플 없음.")
                        continue
                    print(f"  -> {len(samples)}개 샘플 후보 발견.")
                    for sample in samples:
                        if len(collected_files) >= count: break
                        sample_id, filename = sample.get('id'), sample.get('filename', '')
                        file_ext = os.path.splitext(filename)[1].lower()
                        if file_ext in ['.doc', '.docx', '.docm', '.pdf', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx',
                                        '.pptm', '.hwp', '.rtf']:
                            file_path = self._download_triage_sample(sample_id, filename)
                            if file_path:
                                collected_files.append(file_path)
                                with open(file_path, 'rb') as f:
                                    file_hash = hashlib.sha256(f.read()).hexdigest()
                                self._save_sample_metadata(
                                    file_path, file_hash, True, 'triage',
                                    sample.get('family'), 'malware'
                                )
                else:
                    print(f"  -> 쿼리 실패 (상태 코드: {response.status_code}, 메시지: {response.text})")
                time.sleep(5)
            except Exception as e:
                print(f"[Triage] 쿼리 중 오류 발생: {e}")
                time.sleep(15)
                continue
        print(f"[Triage] 총 {len(collected_files)}개 악성 샘플 수집 완료")
        return collected_files

    def collect_clean_samples_verified(self, count: int) -> List[str]:
        """정상 샘플은 수동으로 추가하는 것을 권장"""
        print("[Clean] 자동 정상 샘플 수집 기능이 비활성화되었습니다.")
        print("[Clean] 'import_clean_files.py'를 사용하여 '진짜' 정상 파일을 수동으로 추가해주세요.")
        local_clean_dir = config.DIRECTORIES.get('clean_samples')
        if os.path.exists(local_clean_dir):
            existing_clean_files = [os.path.join(local_clean_dir, f) for f in os.listdir(local_clean_dir) if
                                    os.path.isfile(os.path.join(local_clean_dir, f))]
            print(f"[Clean] 기존에 수집된 로컬 정상 파일 {len(existing_clean_files)}개를 사용합니다.")
            return existing_clean_files[:count]
        return []

    def _download_triage_sample(self, sample_id: str, filename: str) -> str:
        """Tria.ge 샘플 다운로드"""
        try:
            headers = {'Authorization': f'Bearer {self.triage_key}'}
            response = requests.get(f'https://api.tria.ge/v0/samples/{sample_id}/sample', headers=headers, timeout=60)
            if response.status_code == 200:
                os.makedirs(config.DIRECTORIES['malware_samples'], exist_ok=True)
                safe_filename = f"triage_{sample_id}_{filename.replace('/', '_')}"
                file_path = os.path.join(config.DIRECTORIES['malware_samples'], safe_filename)
                with open(file_path, 'wb') as f: f.write(response.content)
                return file_path
        except Exception as e:
            print(f"Triage 다운로드 실패 {sample_id}: {e}")
        return None

    def _save_sample_metadata(self, file_path: str, file_hash: str, is_malicious: bool,
                              source: str, malware_family: str = None, threat_category: str = None):
        """샘플 메타데이터를 RDS에 저장"""
        try:
            s3_key = aws_helper.upload_virus_sample(file_path, file_hash) if config.USE_AWS else None
            db.save_virus_sample(
                file_path=file_path, file_hash=file_hash, is_malicious=is_malicious,
                source=source, malware_family=malware_family,
                threat_category=threat_category, s3_key=s3_key
            )
        except Exception as e:
            print(f"메타데이터 저장 실패: {e}")


def collect_training_data_with_progress(malware_count: int = 200, clean_count: int = 100,
                                        progress_callback=None) -> Tuple[List[str], List[str]]:
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
    # MalwareBazaar와 Tria.ge가 수집 목표를 50:50으로 나눠 갖도록 수정
    if mb_available:
        progress("MalwareBazaar에서 악성 샘플 수집 중...")
        malware_files.extend(client.collect_malware_samples_malware_bazaar(malware_count * 50 // 100))
    if triage_available:
        progress("Tria.ge에서 악성 샘플 수집 중...")
        malware_files.extend(client.collect_malware_samples_triage(malware_count * 50 // 100))

    progress("로컬 정상 샘플 확인 중...")
    clean_files = client.collect_clean_samples_verified(clean_count)

    progress("중복 파일 제거 중...")
    malware_files = remove_duplicates(malware_files)
    clean_files = remove_duplicates(clean_files)

    if clean_files and malware_files and len(clean_files) > len(malware_files) * 0.7:
        clean_files = clean_files[:int(len(malware_files) * 0.7)]
        progress(f"정상 샘플 수를 {len(clean_files)}개로 조정 (악성 대비 70% 이하)")

    progress(f"수집 완료: 악성 {len(malware_files)}개, 정상 {len(clean_files)}개")
    if (len(malware_files) + len(clean_files)) > 0:
        malware_ratio = len(malware_files) / (len(malware_files) + len(clean_files)) * 100
        progress(f"비율: 악성 {malware_ratio:.1f}%, 정상 {100 - malware_ratio:.1f}%")

    return malware_files, clean_files


def remove_duplicates(file_paths: List[str]) -> List[str]:
    unique_files, seen_hashes = [], set()
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