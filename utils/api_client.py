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
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.session = requests.Session()

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

    def download_malware_samples(self, count: int = 20) -> List[str]:
        """MalwareBazaar에서 악성코드 샘플 다운로드"""
        downloaded_files = []

        if not self.malware_bazaar_key:
            print("MalwareBazaar API 키가 없습니다")
            return downloaded_files

        try:
            url = "https://mb-api.abuse.ch/api/v1/"
            headers = {"Auth-Key": self.malware_bazaar_key}

            # 문서 타입별 분류를 위한 딕셔너리
            document_types = {
                'pdf': [],
                'word': [],  # doc, docx
                'excel': [],  # xls, xlsx
                'powerpoint': [],  # ppt, pptx
                'hwp': [],
                'other': []
            }

            print("다양한 문서 형식 샘플 수집 시작...")

            # 전략 1: 최근 1000개 샘플 조회
            print("최근 1000개 샘플 조회 중...")
            data = {"query": "get_recent", "selector": "1000"}

            response = self.session.post(url, data=data, headers=headers, timeout=30)
            all_samples = []

            if response.status_code == 200:
                result = response.json()
                if result.get("query_status") == "ok":
                    all_samples = result.get("data", [])
                    print(f"✓ 최근 샘플 조회 성공: {len(all_samples)}개")

            # 전략 2: 문서 타입별 태그 검색으로 보강
            document_tags = {
                'pdf': ['pdf'],
                'word': ['doc', 'docx', 'word', 'msword'],
                'excel': ['xls', 'xlsx', 'excel', 'spreadsheet'],
                'powerpoint': ['ppt', 'pptx', 'powerpoint', 'presentation'],
                'hwp': ['hwp'],
                'general': ['office', 'document', 'emotet', 'trickbot', 'formbook', 'agent tesla']
            }

            for doc_type, tags in document_tags.items():
                for tag in tags:
                    if len(all_samples) >= 3000:  # 너무 많으면 중단
                        break

                    try:
                        print(f"'{tag}' 태그 검색 중...")
                        tag_data = {"query": "get_taginfo", "tag": tag, "limit": "100"}

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

                        time.sleep(0.5)  # API 제한 대응

                    except Exception as tag_error:
                        print(f"'{tag}' 태그 검색 실패: {tag_error}")
                        continue

            print(f"총 조회된 샘플: {len(all_samples)}개")

            if not all_samples:
                print("조회된 샘플이 없습니다")
                return downloaded_files

            # 문서 파일을 타입별로 분류
            for sample in all_samples:
                try:
                    # None 값 처리
                    file_name = sample.get("file_name") or ""
                    file_type = sample.get("file_type") or ""
                    signature = sample.get("signature") or ""
                    file_type_mime = sample.get("file_type_mime") or ""

                    # 소문자 변환
                    file_name_lower = str(file_name).lower()
                    file_type_lower = str(file_type).lower()
                    signature_lower = str(signature).lower()
                    mime_lower = str(file_type_mime).lower()

                    # 문서 타입 분류
                    classified = False

                    # PDF 분류
                    pdf_indicators = ['.pdf', 'pdf', 'application/pdf']
                    if any(indicator in file_name_lower or indicator in file_type_lower or indicator in mime_lower
                           for indicator in pdf_indicators):
                        document_types['pdf'].append(sample)
                        classified = True

                    # Word 문서 분류
                    elif not classified:
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

                    # 시그니처 기반 문서 분류 (확실한 문서 악성코드들)
                    elif not classified:
                        sig_indicators = ['emotet', 'trickbot', 'qakbot', 'formbook', 'agent tesla', 'lokibot']
                        if any(sig in signature_lower for sig in sig_indicators):
                            # 시그니처로 문서임을 추정할 수 있는 경우
                            pattern_indicators = ['invoice', 'document', 'report', 'statement', 'order', 'contract']
                            if any(pattern in file_name_lower for pattern in pattern_indicators):
                                document_types['other'].append(sample)
                                classified = True

                except Exception:
                    continue

            # 타입별 샘플 수 출력
            print("\n📊 문서 타입별 분류 결과:")
            for doc_type, samples in document_types.items():
                print(f"  {doc_type.upper()}: {len(samples)}개")

            # 각 타입별로 균등하게 다운로드 (최소 2개씩)
            target_per_type = max(2, count // 6)  # 6개 타입으로 나누기
            selected_samples = []

            for doc_type, samples in document_types.items():
                if samples:
                    # 각 타입에서 최대 target_per_type개씩 선택
                    selected = samples[:min(target_per_type, len(samples))]
                    selected_samples.extend(selected)
                    print(f"  └ {doc_type.upper()}: {len(selected)}개 선택")

            # 부족하면 추가 샘플로 채우기
            if len(selected_samples) < count:
                remaining = count - len(selected_samples)
                print(f"추가로 {remaining}개 샘플 필요...")

                # 모든 문서 타입에서 추가 선택
                all_doc_samples = []
                for samples in document_types.values():
                    all_doc_samples.extend(samples)

                # 이미 선택된 것 제외
                selected_hashes = {s.get("sha256_hash") for s in selected_samples}
                additional_samples = [s for s in all_doc_samples
                                      if s.get("sha256_hash") not in selected_hashes]

                selected_samples.extend(additional_samples[:remaining])

            # 최종 선택된 샘플 수
            selected_samples = selected_samples[:count]
            print(f"\n🎯 최종 선택된 샘플: {len(selected_samples)}개")

            if not selected_samples:
                print("다운로드할 문서 샘플이 없습니다")
                return downloaded_files

            os.makedirs("sample/mecro", exist_ok=True)

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

                    # 안전한 파일명 생성 (확장자 포함)
                    safe_chars = "".join(c for c in str(file_name) if c.isalnum() or c in '._-')
                    safe_filename = safe_chars[:50] if safe_chars else f"malware_{i:03d}"

                    # 확장자가 없으면 파일 타입 기반으로 추가
                    if '.' not in safe_filename and file_type != "unknown":
                        safe_filename += f".{file_type}"

                    print(f"다운로드 중 ({i + 1}/{len(selected_samples)}): {safe_filename}")
                    print(f"  └ 타입: {file_type}, SHA256: {sha256_hash[:16]}...")

                    # 파일 다운로드
                    download_data = {"query": "get_file", "sha256_hash": sha256_hash}

                    dl_response = self.session.post(url, data=download_data, headers=headers, timeout=60)

                    if dl_response.status_code == 200 and dl_response.content:
                        # 응답이 JSON 오류인지 확인
                        try:
                            if dl_response.content.startswith(b'{'):
                                error_data = dl_response.json()
                                print(f"  ✗ API 오류: {error_data.get('query_status', 'Unknown')}")
                                continue
                        except:
                            pass  # JSON이 아니면 파일 데이터

                        # ZIP 파일로 저장
                        zip_path = os.path.join("sample/mecro", f"{safe_filename}.zip")

                        with open(zip_path, "wb") as f:
                            f.write(dl_response.content)

                        print(f"  └ ZIP 파일 저장됨 ({len(dl_response.content):,} bytes)")

                        # ZIP 파일 압축 해제 시도
                        extracted = False

                        # pyzipper 시도
                        try:
                            import pyzipper
                            with pyzipper.AESZipFile(zip_path, 'r') as zip_ref:
                                zip_ref.pwd = b'infected'
                                extracted_files = zip_ref.namelist()

                                if extracted_files:
                                    zip_ref.extractall("sample/mecro")

                                    # 첫 번째 파일을 원하는 이름으로 변경
                                    old_path = os.path.join("sample/mecro", extracted_files[0])
                                    new_path = os.path.join("sample/mecro", safe_filename)

                                    if os.path.exists(old_path):
                                        if os.path.exists(new_path):
                                            os.remove(new_path)
                                        os.rename(old_path, new_path)
                                        downloaded_files.append(new_path)
                                        extracted = True
                                        print(f"  ✓ 압축 해제 성공: {safe_filename}")

                            if extracted:
                                os.remove(zip_path)  # ZIP 파일 삭제

                        except ImportError:
                            print("  ! pyzipper 없음, 일반 zipfile 시도...")
                        except Exception as pyzipper_error:
                            print(f"  ! pyzipper 실패: {pyzipper_error}")

                        # 일반 zipfile 시도 (pyzipper 실패 시)
                        if not extracted:
                            try:
                                import zipfile
                                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                                    zip_ref.setpassword(b'infected')
                                    extracted_files = zip_ref.namelist()

                                    if extracted_files:
                                        zip_ref.extractall("sample/mecro")

                                        old_path = os.path.join("sample/mecro", extracted_files[0])
                                        new_path = os.path.join("sample/mecro", safe_filename)

                                        if os.path.exists(old_path):
                                            if os.path.exists(new_path):
                                                os.remove(new_path)
                                            os.rename(old_path, new_path)
                                            downloaded_files.append(new_path)
                                            extracted = True
                                            print(f"  ✓ 압축 해제 성공 (zipfile): {safe_filename}")

                                if extracted:
                                    os.remove(zip_path)

                            except Exception as zipfile_error:
                                print(f"  ! zipfile 실패: {zipfile_error}")

                        # 압축 해제 실패 시 ZIP 파일 그대로 저장
                        if not extracted:
                            downloaded_files.append(zip_path)
                            print(f"  ✓ ZIP 파일로 저장: {safe_filename}.zip")

                    else:
                        print(f"  ✗ 다운로드 실패: HTTP {dl_response.status_code}")
                        if dl_response.content:
                            try:
                                error_response = dl_response.json()
                                print(f"    오류: {error_response.get('query_status', 'Unknown')}")
                            except:
                                print(f"    응답 길이: {len(dl_response.content)} bytes")

                except Exception as download_error:
                    print(f"  ✗ 다운로드 오류: {download_error}")

                # API 제한 대응
                time.sleep(3)

        except Exception as e:
            print(f"샘플 다운로드 중 전체 오류: {e}")

        # 다운로드 결과 분석
        print(f"\n📁 총 {len(downloaded_files)}개 파일 다운로드 완료")

        if downloaded_files:
            print("\n📊 다운로드된 파일 타입별 분류:")
            type_counts = {'pdf': 0, 'doc': 0, 'xls': 0, 'ppt': 0, 'hwp': 0, 'zip': 0, 'other': 0}

            for file_path in downloaded_files:
                file_name = os.path.basename(file_path).lower()
                file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

                if '.pdf' in file_name:
                    type_counts['pdf'] += 1
                elif '.doc' in file_name:
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

            print("\n🏷️ 타입별 요약:")
            for file_type, count in type_counts.items():
                if count > 0:
                    print(f"  {file_type.upper()}: {count}개")

        return downloaded_files

    def get_clean_samples(self, count: int = 20) -> List[str]:
        """정상 문서 샘플 생성 (더미 데이터)"""
        clean_files = []
        os.makedirs("sample/clear", exist_ok=True)

        try:
            # 간단한 정상 PDF 생성
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import letter

            for i in range(count):
                file_path = f"sample/clear/clean_document_{i:03d}.pdf"

                c = canvas.Canvas(file_path, pagesize=letter)
                c.drawString(100, 750, f"Clean Document #{i + 1}")
                c.drawString(100, 730, "This is a normal, safe document.")
                c.drawString(100, 710, f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}")
                c.save()

                clean_files.append(file_path)

        except ImportError:
            # reportlab이 없으면 텍스트 파일로 대체
            for i in range(count):
                file_path = f"sample/clear/clean_document_{i:03d}.txt"

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
            # 파일 해시 계산
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            # VirusTotal에서 결과 조회
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


def collect_training_data(malware_count: int = 15, clean_count: int = 15):
    """훈련 데이터 수집"""
    client = APIClient()

    print("=== 훈련 데이터 수집 시작 ===")

    # 악성 샘플 다운로드
    print(f"악성 샘플 {malware_count}개 다운로드 중...")
    malware_files = client.download_malware_samples(malware_count)
    print(f"악성 샘플 다운로드 완료: {len(malware_files)}개")

    # 정상 샘플 생성
    print(f"정상 샘플 {clean_count}개 생성 중...")
    clean_files = client.get_clean_samples(clean_count)
    print(f"정상 샘플 생성 완료: {len(clean_files)}개")

    print("=== 데이터 수집 완료 ===")

    return malware_files, clean_files


if __name__ == "__main__":
    collect_training_data()