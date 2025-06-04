import requests
import os
import time
import hashlib
from typing import List, Dict, Optional
from dotenv import load_dotenv
import config

load_dotenv()


class APIClient:
    def __init__(self):
        self.malware_bazaar_key = os.getenv('MALWARE_BAZAAR_API_KEY')
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
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

    def download_malware_samples(self, count: int = 500) -> List[str]:
        """MalwareBazaar에서 Office 및 HWP 악성코드 샘플 다운로드"""
        downloaded_files = []

        if not self.malware_bazaar_key:
            print("MalwareBazaar API 키가 없습니다")
            return downloaded_files

        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            headers = {"Auth-Key": self.malware_bazaar_key}

            # Office 및 HWP 문서 타입만 분류
            document_types = {
                'word': [],
                'excel': [],
                'powerpoint': [],
                'hwp': [],
                'general': []
            }

            print("Office 및 HWP 문서 샘플 수집 시작...")

            # 최근 2000개 샘플 조회로 확대
            print("최근 2000개 샘플 조회 중...")
            data = {"query": "get_recent", "selector": "2000"}

            response = self.session.post(url, data=data, headers=headers, timeout=30)
            all_samples = []

            if response.status_code == 200:
                result = response.json()
                if result.get("query_status") == "ok":
                    all_samples = result.get("data", [])
                    print(f"최근 샘플 조회 성공: {len(all_samples)}개")

            # Office 및 HWP 관련 태그로 추가 검색
            office_tags = {
                'word': ['doc', 'docx', 'word', 'msword', 'wordprocessingml'],
                'excel': ['xls', 'xlsx', 'excel', 'spreadsheet', 'spreadsheetml'],
                'powerpoint': ['ppt', 'pptx', 'powerpoint', 'presentation', 'presentationml'],
                'hwp': ['hwp'],
                'general': ['office', 'emotet', 'trickbot', 'formbook', 'agent tesla', 'lokibot']
            }

            for doc_type, tags in office_tags.items():
                for tag in tags:
                    if len(all_samples) >= 5000:
                        break

                    try:
                        print(f"'{tag}' 태그 검색 중...")
                        tag_data = {"query": "get_taginfo", "tag": tag, "limit": "200"}

                        tag_response = self.session.post(url, data=tag_data, headers=headers, timeout=30)

                        if tag_response.status_code == 200:
                            tag_result = tag_response.json()
                            if tag_result.get("query_status") == "ok":
                                tag_samples = tag_result.get("data", [])
                                print(f"  └ '{tag}' 태그: {len(tag_samples)}개 발견")

                                # 중복 제거하며 추가
                                existing_hashes = {s.get("sha256_hash") for s in all_samples}
                                for sample in tag_samples:
                                    hash_val = sample.get("sha256_hash")
                                    if hash_val and hash_val not in existing_hashes:
                                        all_samples.append(sample)
                                        existing_hashes.add(hash_val)

                        time.sleep(0.5)

                    except Exception as tag_error:
                        print(f"'{tag}' 태그 검색 실패: {tag_error}")
                        continue

            print(f"총 조회된 샘플: {len(all_samples)}개")

            if not all_samples:
                print("조회된 샘플이 없습니다")
                return downloaded_files

            # Office 및 HWP 파일만 분류
            for sample in all_samples:
                try:
                    file_name = sample.get("file_name") or ""
                    file_type = sample.get("file_type") or ""
                    signature = sample.get("signature") or ""
                    file_type_mime = sample.get("file_type_mime") or ""

                    file_name_lower = str(file_name).lower()
                    file_type_lower = str(file_type).lower()
                    signature_lower = str(signature).lower()
                    mime_lower = str(file_type_mime).lower()

                    classified = False

                    # Word 문서 분류
                    word_indicators = ['.doc', '.docx', 'doc', 'docx', 'msword', 'wordprocessingml']
                    if any(indicator in file_name_lower or indicator in file_type_lower or indicator in mime_lower
                           for indicator in word_indicators):
                        document_types['word'].append(sample)
                        classified = True

                    # Excel 분류
                    elif not classified:
                        excel_indicators = ['.xls', '.xlsx', 'xls', 'xlsx', 'excel', 'spreadsheetml']
                        if any(indicator in file_name_lower or indicator in file_type_lower or indicator in mime_lower
                               for indicator in excel_indicators):
                            document_types['excel'].append(sample)
                            classified = True

                    # PowerPoint 분류
                    elif not classified:
                        ppt_indicators = ['.ppt', '.pptx', 'ppt', 'pptx', 'powerpoint', 'presentationml']
                        if any(indicator in file_name_lower or indicator in file_type_lower or indicator in mime_lower
                               for indicator in ppt_indicators):
                            document_types['powerpoint'].append(sample)
                            classified = True

                    # HWP 분류
                    elif not classified:
                        hwp_indicators = ['.hwp', '.hwpx', '.hwpml', 'hwp']
                        if any(indicator in file_name_lower or indicator in file_type_lower
                               for indicator in hwp_indicators):
                            document_types['hwp'].append(sample)
                            classified = True

                    # Office 관련 악성코드 시그니처
                    elif not classified:
                        office_signatures = ['emotet', 'trickbot', 'qakbot', 'formbook', 'agent tesla', 'lokibot']
                        if any(sig in signature_lower for sig in office_signatures):
                            office_patterns = ['invoice', 'document', 'report', 'statement', 'order', 'contract']
                            if any(pattern in file_name_lower for pattern in office_patterns):
                                document_types['general'].append(sample)
                                classified = True

                except Exception:
                    continue

            # 타입별 샘플 수 출력
            print("\n문서 타입별 분류 결과:")
            for doc_type, samples in document_types.items():
                print(f"  {doc_type.upper()}: {len(samples)}개")

            # 각 타입별로 균등하게 다운로드
            target_per_type = max(50, count // 5)
            selected_samples = []

            for doc_type, samples in document_types.items():
                if samples:
                    selected = samples[:min(target_per_type, len(samples))]
                    selected_samples.extend(selected)
                    print(f"  └ {doc_type.upper()}: {len(selected)}개 선택")

            # 부족하면 추가 샘플로 채우기
            if len(selected_samples) < count:
                remaining = count - len(selected_samples)
                print(f"추가로 {remaining}개 샘플 필요...")

                all_doc_samples = []
                for samples in document_types.values():
                    all_doc_samples.extend(samples)

                selected_hashes = {s.get("sha256_hash") for s in selected_samples}
                additional_samples = [s for s in all_doc_samples
                                      if s.get("sha256_hash") not in selected_hashes]

                selected_samples.extend(additional_samples[:remaining])

            selected_samples = selected_samples[:count]
            print(f"\n최종 선택된 샘플: {len(selected_samples)}개")

            if not selected_samples:
                print("다운로드할 문서 샘플이 없습니다")
                return downloaded_files

            os.makedirs(config.DIRECTORIES['malware_samples'], exist_ok=True)

            # 샘플 다운로드
            for i, sample in enumerate(selected_samples):
                if len(downloaded_files) >= count:
                    break

                try:
                    sha256_hash = sample.get("sha256_hash")
                    file_name = sample.get("file_name") or f"malware_{i:03d}"
                    file_type = sample.get("file_type") or "unknown"

                    if not sha256_hash:
                        print("SHA256 해시가 없는 샘플 건너뜀")
                        continue

                    # 안전한 파일명 생성
                    safe_chars = "".join(c for c in str(file_name) if c.isalnum() or c in '._-')
                    safe_filename = safe_chars[:50] if safe_chars else f"malware_{i:03d}"

                    if '.' not in safe_filename and file_type != "unknown":
                        safe_filename += f".{file_type}"

                    print(f"다운로드 중 ({i + 1}/{len(selected_samples)}): {safe_filename}")
                    print(f"  └ 타입: {file_type}, SHA256: {sha256_hash[:16]}...")

                    # 파일 다운로드
                    download_data = {"query": "get_file", "sha256_hash": sha256_hash}

                    dl_response = self.session.post(url, data=download_data, headers=headers, timeout=60)

                    if dl_response.status_code == 200 and dl_response.content:
                        # JSON 오류 응답 확인
                        try:
                            if dl_response.content.startswith(b'{'):
                                error_data = dl_response.json()
                                print(f"  API 오류: {error_data.get('query_status', 'Unknown')}")
                                continue
                        except:
                            pass

                        # ZIP 파일 저장
                        zip_path = os.path.join(config.DIRECTORIES['malware_samples'], f"{safe_filename}.zip")

                        with open(zip_path, "wb") as f:
                            f.write(dl_response.content)

                        print(f"  └ ZIP 파일 저장됨 ({len(dl_response.content):,} bytes)")

                        # ZIP 압축 해제
                        extracted = False

                        # pyzipper 시도
                        try:
                            import pyzipper
                            with pyzipper.AESZipFile(zip_path, 'r') as zip_ref:
                                zip_ref.pwd = b'infected'
                                extracted_files = zip_ref.namelist()

                                if extracted_files:
                                    zip_ref.extractall(config.DIRECTORIES['malware_samples'])

                                    old_path = os.path.join(config.DIRECTORIES['malware_samples'], extracted_files[0])
                                    new_path = os.path.join(config.DIRECTORIES['malware_samples'], safe_filename)

                                    if os.path.exists(old_path):
                                        if os.path.exists(new_path):
                                            os.remove(new_path)
                                        os.rename(old_path, new_path)
                                        downloaded_files.append(new_path)
                                        extracted = True
                                        print(f"  압축 해제 성공: {safe_filename}")

                            if extracted:
                                os.remove(zip_path)

                        except ImportError:
                            print("  pyzipper 없음, 일반 zipfile 시도...")
                        except Exception as pyzipper_error:
                            print(f"  pyzipper 실패: {pyzipper_error}")

                        # 일반 zipfile 시도
                        if not extracted:
                            try:
                                import zipfile
                                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                                    zip_ref.setpassword(b'infected')
                                    extracted_files = zip_ref.namelist()

                                    if extracted_files:
                                        zip_ref.extractall(config.DIRECTORIES['malware_samples'])

                                        old_path = os.path.join(config.DIRECTORIES['malware_samples'], extracted_files[0])
                                        new_path = os.path.join(config.DIRECTORIES['malware_samples'], safe_filename)

                                        if os.path.exists(old_path):
                                            if os.path.exists(new_path):
                                                os.remove(new_path)
                                            os.rename(old_path, new_path)
                                            downloaded_files.append(new_path)
                                            extracted = True
                                            print(f"  압축 해제 성공 (zipfile): {safe_filename}")

                                if extracted:
                                    os.remove(zip_path)

                            except Exception as zipfile_error:
                                print(f"  zipfile 실패: {zipfile_error}")

                        # 압축 해제 실패 시 ZIP 파일로 저장
                        if not extracted:
                            downloaded_files.append(zip_path)
                            print(f"  ZIP 파일로 저장: {safe_filename}.zip")

                    else:
                        print(f"  다운로드 실패: HTTP {dl_response.status_code}")
                        if dl_response.content:
                            try:
                                error_response = dl_response.json()
                                print(f"    오류: {error_response.get('query_status', 'Unknown')}")
                            except:
                                print(f"    응답 길이: {len(dl_response.content)} bytes")

                except Exception as download_error:
                    print(f"  다운로드 오류: {download_error}")

                time.sleep(2)

        except Exception as e:
            print(f"샘플 다운로드 중 전체 오류: {e}")

        print(f"\n총 {len(downloaded_files)}개 파일 다운로드 완료")

        if downloaded_files:
            print("\n다운로드된 파일 타입별 분류:")
            type_counts = {'doc': 0, 'xls': 0, 'ppt': 0, 'hwp': 0, 'zip': 0, 'other': 0}

            for file_path in downloaded_files:
                file_name = os.path.basename(file_path).lower()
                file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

                if '.doc' in file_name:
                    type_counts['doc'] += 1
                elif '.xls' in file_name:
                    type_counts['xls'] += 1
                elif '.ppt' in file_name:
                    type_counts['ppt'] += 1
                elif '.hwp' in file_name:
                    type_counts['hwp'] += 1
                elif '.zip' in file_name:
                    type_counts['zip'] += 1
                else:
                    type_counts['other'] += 1

                print(f"  - {os.path.basename(file_path)} ({file_size:,} bytes)")

            print("\n타입별 요약:")
            for file_type, count in type_counts.items():
                if count > 0:
                    print(f"  {file_type.upper()}: {count}개")

        return downloaded_files

    def get_clean_samples(self, count: int = 500) -> List[str]:
        """정상 문서 샘플 생성 (clear 폴더에 저장)"""
        clean_files = []
        os.makedirs(config.DIRECTORIES['clean_samples'], exist_ok=True)

        try:
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import letter

            # Office 문서 형식별로 더미 생성
            office_types = ['doc', 'xls', 'ppt']
            per_type = count // 4

            # PDF 생성
            for i in range(per_type):
                file_path = os.path.join(config.DIRECTORIES['clean_samples'], f"clean_document_{i:03d}.pdf")
                c = canvas.Canvas(file_path, pagesize=letter)
                c.drawString(100, 750, f"Clean Document #{i + 1}")
                c.drawString(100, 730, "This is a normal, safe document.")
                c.drawString(100, 710, f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}")
                c.save()
                clean_files.append(file_path)

            # 텍스트 파일로 Office 문서 시뮬레이션
            for office_type in office_types:
                for i in range(per_type):
                    file_path = os.path.join(config.DIRECTORIES['clean_samples'], f"clean_{office_type}_{i:03d}.txt")
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(f"Clean {office_type.upper()} Document #{i + 1}\n")
                        f.write("This is a normal, safe document.\n")
                        f.write(f"Type: {office_type.upper()}\n")
                        f.write(f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    clean_files.append(file_path)

        except ImportError:
            # reportlab이 없으면 텍스트 파일로만 생성
            for i in range(count):
                file_path = os.path.join(config.DIRECTORIES['clean_samples'], f"clean_document_{i:03d}.txt")
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(f"Clean Document #{i + 1}\n")
                    f.write("This is a normal, safe document.\n")
                    f.write(f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                clean_files.append(file_path)

        return clean_files

    def check_file_with_virustotal(self, file_path: str) -> Dict:
        """VirusTotal로 파일 검사"""
        if not self.virustotal_key:
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
                return {"error": f"VirusTotal에 데이터 없음 (404)"}

        except Exception as e:
            return {"error": f"검사 중 오류: {str(e)}"}


def collect_training_data(malware_count: int = 500, clean_count: int = 500):
    """훈련 데이터 수집 v2.2"""
    client = APIClient()

    print("=== 훈련 데이터 수집 시작 v2.2 ===")

    print(f"악성 샘플 {malware_count}개 다운로드 중...")
    malware_files = client.download_malware_samples(malware_count)
    print(f"악성 샘플 다운로드 완료: {len(malware_files)}개")

    print(f"정상 샘플 {clean_count}개 생성 중...")
    clean_files = client.get_clean_samples(clean_count)
    print(f"정상 샘플 생성 완료: {len(clean_files)}개")

    print("=== 데이터 수집 완료 ===")

    return malware_files, clean_files


if __name__ == "__main__":
    collect_training_data()