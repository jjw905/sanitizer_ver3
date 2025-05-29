import os
import re
import hashlib
import zipfile
from typing import List, Dict, Any
import numpy as np
from PyPDF2 import PdfReader
from PyPDF2.generic import IndirectObject
from oletools.olevba import VBA_Parser


class FeatureExtractor:
    def __init__(self):
        self.suspicious_keywords = [
            'javascript', 'shell', 'cmd', 'exec', 'eval', 'document.write',
            'activex', 'wscript', 'powershell', 'base64', 'decode', 'unescape',
            'fromcharcode', 'string.prototype', 'function', 'var ', 'if(',
            'for(', 'while(', 'try{', 'catch(', 'throw', 'new array',
            'document.', 'window.', 'location.', 'navigator.', 'screen.',
            'history.', 'frames', 'parent.', 'top.', 'self.', 'opener.',
            'urlmon', 'wininet', 'kernel32', 'advapi32', 'user32'
        ]

        self.office_suspicious = [
            'auto_open', 'workbook_open', 'document_open', 'auto_exec',
            'shell', 'environ', 'createobject', 'getobject', 'callbyname',
            'application.run', 'sendkeys', 'timer', 'now', 'format',
            'dir', 'kill', 'filecopy', 'mkdir', 'rmdir', 'chdir'
        ]

    def extract_file_features(self, file_path: str) -> Dict[str, Any]:
        """파일에서 특징 추출"""
        features = {
            'file_size': 0,
            'entropy': 0.0,
            'suspicious_keywords_count': 0,
            'has_macro': False,
            'pdf_js_count': 0,
            'pdf_openaction': False,
            'file_extension': '',
            'metadata_anomaly': False,
            'string_entropy': 0.0,
            'compression_ratio': 0.0
        }

        try:
            # 기본 파일 정보
            file_size = os.path.getsize(file_path)
            features['file_size'] = file_size
            features['file_extension'] = os.path.splitext(file_path)[1].lower()

            # 파일 내용 읽기
            with open(file_path, 'rb') as f:
                content = f.read()

            # 엔트로피 계산
            features['entropy'] = self._calculate_entropy(content)

            # 파일 타입별 특징 추출
            ext = features['file_extension']

            if ext == '.pdf':
                features.update(self._extract_pdf_features(file_path, content))
            elif ext in ['.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm']:
                features.update(self._extract_office_features(file_path, content))
            elif ext in ['.hwp', '.hwpx', '.hwpml']:
                features.update(self._extract_hwp_features(content))

            # 의심 키워드 카운트
            content_str = content.decode('utf-8', errors='ignore').lower()
            features['suspicious_keywords_count'] = sum(
                content_str.count(keyword) for keyword in self.suspicious_keywords
            )

            # 문자열 엔트로피
            features['string_entropy'] = self._calculate_string_entropy(content_str)

            # 압축률 (ZIP 기반 파일들)
            if ext in ['.docx', '.xlsx', '.pptx']:
                features['compression_ratio'] = self._calculate_compression_ratio(file_path)

        except Exception as e:
            print(f"특징 추출 중 오류 ({file_path}): {e}")

        return features

    def _calculate_entropy(self, data: bytes) -> float:
        """바이트 엔트로피 계산"""
        if not data:
            return 0.0

        # 바이트 빈도 계산
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # 엔트로피 계산
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * np.log2(probability)

        return entropy

    def _calculate_string_entropy(self, text: str) -> float:
        """문자열 엔트로피 계산"""
        if not text:
            return 0.0

        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            entropy -= probability * np.log2(probability)

        return entropy

    def _extract_pdf_features(self, file_path: str, content: bytes) -> Dict[str, Any]:
        """PDF 특징 추출"""
        features = {
            'pdf_js_count': 0,
            'pdf_openaction': False,
            'pdf_forms': False,
            'pdf_encryption': False,
            'pdf_pages': 0
        }

        try:
            reader = PdfReader(file_path)
            features['pdf_pages'] = len(reader.pages)
            features['pdf_encryption'] = reader.is_encrypted

            # JavaScript 검사
            root = reader.trailer.get("/Root", {})
            if isinstance(root, IndirectObject):
                root = root.get_object()

            js_count = self._count_js_in_pdf_object(root)
            features['pdf_js_count'] = js_count

            # OpenAction 검사
            features['pdf_openaction'] = "/OpenAction" in root or "/AA" in root

            # Forms 검사
            features['pdf_forms'] = "/AcroForm" in root

        except Exception as e:
            print(f"PDF 특징 추출 오류: {e}")
            # 내용 기반 간단 검사
            content_lower = content.lower()
            features['pdf_js_count'] = content_lower.count(b'javascript')
            features['pdf_openaction'] = b'openaction' in content_lower

        return features

    def _count_js_in_pdf_object(self, obj, count=0) -> int:
        """PDF 객체에서 JavaScript 카운트"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if str(key) in ["/JavaScript", "/JS"]:
                    count += 1
                count = self._count_js_in_pdf_object(value, count)
        elif isinstance(obj, list):
            for item in obj:
                count = self._count_js_in_pdf_object(item, count)
        return count

    def _extract_office_features(self, file_path: str, content: bytes) -> Dict[str, Any]:
        """Office 문서 특징 추출"""
        features = {
            'has_macro': False,
            'macro_suspicious_count': 0,
            'has_external_links': False,
            'xml_complexity': 0
        }

        try:
            # 매크로 검사
            vba_parser = VBA_Parser(file_path)
            features['has_macro'] = vba_parser.detect_vba_macros()

            if features['has_macro']:
                vba_code = ""
                for (filename, stream_path, vba_filename, vba_code_chunk) in vba_parser.extract_macros():
                    vba_code += vba_code_chunk.lower()

                # 의심스러운 매크로 함수 카운트
                features['macro_suspicious_count'] = sum(
                    vba_code.count(keyword) for keyword in self.office_suspicious
                )

            # ZIP 구조 분석
            try:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    file_list = zip_ref.namelist()
                    features['xml_complexity'] = len(file_list)

                    # 외부 링크 검사
                    for file_name in file_list:
                        if 'external' in file_name.lower() or 'link' in file_name.lower():
                            features['has_external_links'] = True
                            break
            except:
                pass

        except Exception as e:
            print(f"Office 특징 추출 오류: {e}")

        return features

    def _extract_hwp_features(self, content: bytes) -> Dict[str, Any]:
        """HWP 파일 특징 추출"""
        features = {
            'hwp_scripts': 0,
            'hwp_ole_objects': 0
        }

        try:
            # 스크립트 패턴 검사
            script_patterns = [b'script', b'javascript', b'vbscript']
            for pattern in script_patterns:
                features['hwp_scripts'] += content.count(pattern)

            # OLE 객체 검사
            ole_patterns = [b'ole', b'object', b'embed']
            for pattern in ole_patterns:
                features['hwp_ole_objects'] += content.count(pattern)

        except Exception as e:
            print(f"HWP 특징 추출 오류: {e}")

        return features

    def _calculate_compression_ratio(self, file_path: str) -> float:
        """압축률 계산"""
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                total_compressed = 0
                total_uncompressed = 0

                for info in zip_ref.infolist():
                    total_compressed += info.compress_size
                    total_uncompressed += info.file_size

                if total_uncompressed > 0:
                    return total_compressed / total_uncompressed
        except:
            pass

        return 0.0

    def extract_features_batch(self, file_paths: List[str]) -> np.ndarray:
        """배치 특징 추출"""
        features_list = []

        for file_path in file_paths:
            features = self.extract_file_features(file_path)
            # 수치형 특징만 추출
            numeric_features = [
                features['file_size'],
                features['entropy'],
                features['suspicious_keywords_count'],
                int(features['has_macro']),
                features['pdf_js_count'],
                int(features['pdf_openaction']),
                features.get('pdf_pages', 0),
                int(features.get('pdf_encryption', False)),
                features.get('macro_suspicious_count', 0),
                int(features.get('has_external_links', False)),
                features.get('xml_complexity', 0),
                features.get('hwp_scripts', 0),
                features.get('hwp_ole_objects', 0),
                features['string_entropy'],
                features['compression_ratio']
            ]
            features_list.append(numeric_features)

        return np.array(features_list)


if __name__ == "__main__":
    # 테스트
    extractor = FeatureExtractor()

    # 샘플 파일이 있다면 테스트
    if os.path.exists("sample/mecro"):
        files = [os.path.join("sample/mecro", f) for f in os.listdir("sample/mecro")][:5]
        if files:
            features = extractor.extract_features_batch(files)
            print(f"특징 추출 완료: {features.shape}")
            print(f"첫 번째 파일 특징: {features[0] if len(features) > 0 else 'None'}")