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
        # 악성코드 패밀리별 시그니처 패턴
        self.malware_signatures = {
            'emotet': ['emotet', 'epoch', 'mealybug'],
            'trickbot': ['trickbot', 'trickster', 'anchor'],
            'qakbot': ['qakbot', 'qbot', 'pinkslipbot'],
            'formbook': ['formbook', 'xloader'],
            'agent_tesla': ['agent tesla', 'agenttesla', 'origin logger'],
            'lokibot': ['lokibot', 'loki', 'keylogger'],
            'dridex': ['dridex', 'bugat', 'cridex'],
            'ursnif': ['ursnif', 'gozi', 'isfb'],
            'ransomware': ['wannacry', 'petya', 'ryuk', 'sodinokibi', 'revil'],
            'banker': ['banker', 'banking trojan', 'zeus', 'tinba'],
            'downloader': ['downloader', 'dropper', 'loader'],
            'backdoor': ['backdoor', 'rat', 'remote access'],
            'spyware': ['spyware', 'keylogger', 'infostealer']
        }

        # 의심 키워드 분류
        self.suspicious_keywords = {
            'script_execution': ['javascript', 'vbscript', 'jscript', 'powershell', 'cmd', 'shell', 'exec'],
            'system_access': ['kernel32', 'ntdll', 'advapi32', 'user32', 'wininet', 'urlmon'],
            'persistence': ['autostart', 'startup', 'registry', 'scheduled task', 'service'],
            'network': ['http', 'https', 'ftp', 'download', 'upload', 'socket', 'connect'],
            'evasion': ['base64', 'decode', 'decrypt', 'obfuscate', 'encode'],
            'document_exploit': ['document.write', 'activex', 'oleobject', 'embedded']
        }

        self.office_suspicious = [
            'auto_open', 'workbook_open', 'document_open', 'auto_exec',
            'shell', 'environ', 'createobject', 'getobject', 'callbyname',
            'application.run', 'sendkeys', 'timer', 'now', 'format',
            'dir', 'kill', 'filecopy', 'mkdir', 'rmdir', 'chdir'
        ]

    def extract_file_features(self, file_path: str) -> Dict[str, Any]:
        """파일에서 특징 추출 (악성코드 유형 분석 포함)"""
        features = {
            'file_size': 0,
            'entropy': 0.0,
            'suspicious_keywords_count': 0,
            'has_macro': False,
            'pdf_js_count': 0,
            'pdf_openaction': False,
            'file_extension': '',
            'string_entropy': 0.0,
            'compression_ratio': 0.0,
            'malware_family': 'unknown',
            'threat_category': 'unknown',
            'risk_indicators': []
        }

        try:
            file_size = os.path.getsize(file_path)
            features['file_size'] = file_size
            features['file_extension'] = os.path.splitext(file_path)[1].lower()

            with open(file_path, 'rb') as f:
                content = f.read()

            features['entropy'] = self._calculate_entropy(content)

            ext = features['file_extension']

            if ext == '.pdf':
                features.update(self._extract_pdf_features(file_path, content))
            elif ext in ['.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm']:
                features.update(self._extract_office_features(file_path, content))
            elif ext in ['.hwp', '.hwpx', '.hwpml']:
                features.update(self._extract_hwp_features(content))

            # 악성코드 패밀리 및 유형 분석
            content_str = content.decode('utf-8', errors='ignore').lower()
            features.update(self._analyze_malware_type(content_str, file_path))

            # 위험 지표 분석
            features['risk_indicators'] = self._analyze_risk_indicators(content_str, features)

            # 의심 키워드 분류별 카운트
            keyword_analysis = self._analyze_suspicious_keywords(content_str)
            features.update(keyword_analysis)

            features['string_entropy'] = self._calculate_string_entropy(content_str)

            if ext in ['.docx', '.xlsx', '.pptx']:
                features['compression_ratio'] = self._calculate_compression_ratio(file_path)

        except Exception as e:
            print(f"특징 추출 중 오류 ({os.path.basename(file_path)}): {e}")

        return features

    def _analyze_malware_type(self, content_str: str, file_path: str) -> Dict[str, str]:
        """악성코드 패밀리 및 유형 분석"""
        malware_info = {
            'malware_family': 'unknown',
            'threat_category': 'unknown',
            'confidence_level': 'low'
        }

        # 파일명 기반 분석
        filename_lower = os.path.basename(file_path).lower()

        # 시그니처 매칭
        for family, signatures in self.malware_signatures.items():
            for signature in signatures:
                if signature in content_str or signature in filename_lower:
                    malware_info['malware_family'] = family
                    malware_info['confidence_level'] = 'high'

                    # 패밀리에 따른 카테고리 분류
                    if family in ['emotet', 'trickbot', 'qakbot']:
                        malware_info['threat_category'] = 'banking_trojan'
                    elif family in ['formbook', 'agent_tesla', 'lokibot']:
                        malware_info['threat_category'] = 'infostealer'
                    elif family in ['dridex', 'ursnif']:
                        malware_info['threat_category'] = 'financial_malware'
                    elif 'ransomware' in family:
                        malware_info['threat_category'] = 'ransomware'
                    else:
                        malware_info['threat_category'] = 'generic_malware'

                    return malware_info

        # 일반적인 패턴 기반 분류
        if any(keyword in content_str for keyword in ['ransom', 'encrypt', 'bitcoin', 'decrypt']):
            malware_info['threat_category'] = 'ransomware'
            malware_info['confidence_level'] = 'medium'
        elif any(keyword in content_str for keyword in ['keylog', 'password', 'steal', 'grab']):
            malware_info['threat_category'] = 'infostealer'
            malware_info['confidence_level'] = 'medium'
        elif any(keyword in content_str for keyword in ['download', 'payload', 'stage2']):
            malware_info['threat_category'] = 'downloader'
            malware_info['confidence_level'] = 'medium'
        elif any(keyword in content_str for keyword in ['backdoor', 'rat', 'remote']):
            malware_info['threat_category'] = 'backdoor'
            malware_info['confidence_level'] = 'medium'

        return malware_info

    def _analyze_suspicious_keywords(self, content_str: str) -> Dict[str, int]:
        """의심 키워드 분류별 분석"""
        keyword_counts = {}

        for category, keywords in self.suspicious_keywords.items():
            count = sum(content_str.count(keyword) for keyword in keywords)
            keyword_counts[f'{category}_count'] = count

        # 전체 의심 키워드 수
        keyword_counts['suspicious_keywords_count'] = sum(keyword_counts.values())

        return keyword_counts

    def _analyze_risk_indicators(self, content_str: str, features: Dict) -> List[str]:
        """위험 지표 분석"""
        indicators = []

        # 매크로 관련
        if features.get('has_macro', False):
            macro_count = features.get('macro_suspicious_count', 0)
            if macro_count > 10:
                indicators.append('고위험_매크로')
            elif macro_count > 5:
                indicators.append('중위험_매크로')
            elif macro_count > 0:
                indicators.append('매크로_포함')

        # PDF JavaScript 관련
        if features.get('pdf_js_count', 0) > 0:
            js_count = features['pdf_js_count']
            if js_count > 5:
                indicators.append('다수_JavaScript')
            else:
                indicators.append('JavaScript_포함')

        # 자동실행 관련
        if features.get('pdf_openaction', False):
            indicators.append('자동실행_설정')

        # 암호화/인코딩 패턴
        encoding_patterns = ['base64', 'decode', 'unescape', 'fromcharcode']
        if sum(content_str.count(pattern) for pattern in encoding_patterns) > 3:
            indicators.append('인코딩_패턴')

        # 네트워크 활동
        network_patterns = ['http://', 'https://', 'ftp://', 'connect', 'socket']
        if sum(content_str.count(pattern) for pattern in network_patterns) > 2:
            indicators.append('네트워크_활동')

        # 시스템 명령
        system_patterns = ['cmd', 'powershell', 'shell', 'exec']
        if sum(content_str.count(pattern) for pattern in system_patterns) > 2:
            indicators.append('시스템_명령')

        return indicators

    def _calculate_entropy(self, data: bytes) -> float:
        """바이트 엔트로피 계산"""
        if not data:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

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

            root = reader.trailer.get("/Root", {})
            if isinstance(root, IndirectObject):
                root = root.get_object()

            features['pdf_js_count'] = self._count_js_in_pdf_object(root)
            features['pdf_openaction'] = "/OpenAction" in root or "/AA" in root
            features['pdf_forms'] = "/AcroForm" in root

        except Exception:
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
            vba_parser = VBA_Parser(file_path)
            features['has_macro'] = vba_parser.detect_vba_macros()

            if features['has_macro']:
                vba_code = ""
                for (filename, stream_path, vba_filename, vba_code_chunk) in vba_parser.extract_macros():
                    vba_code += vba_code_chunk.lower()

                features['macro_suspicious_count'] = sum(
                    vba_code.count(keyword) for keyword in self.office_suspicious
                )

            try:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    file_list = zip_ref.namelist()
                    features['xml_complexity'] = len(file_list)

                    for file_name in file_list:
                        if 'external' in file_name.lower() or 'link' in file_name.lower():
                            features['has_external_links'] = True
                            break
            except:
                pass

        except Exception:
            pass

        return features

    def _extract_hwp_features(self, content: bytes) -> Dict[str, Any]:
        """HWP 파일 특징 추출"""
        features = {
            'hwp_scripts': 0,
            'hwp_ole_objects': 0
        }

        try:
            script_patterns = [b'script', b'javascript', b'vbscript']
            for pattern in script_patterns:
                features['hwp_scripts'] += content.count(pattern)

            ole_patterns = [b'ole', b'object', b'embed']
            for pattern in ole_patterns:
                features['hwp_ole_objects'] += content.count(pattern)

        except Exception:
            pass

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
        """배치 특징 추출 (최적화된 버전)"""
        features_list = []

        for file_path in file_paths:
            features = self.extract_file_features(file_path)

            # 수치형 특징만 추출 (확장된 특징 세트)
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

    def get_threat_summary(self, features: Dict[str, Any]) -> str:
        """위협 요약 정보 생성"""
        malware_family = features.get('malware_family', 'unknown')
        threat_category = features.get('threat_category', 'unknown')
        risk_indicators = features.get('risk_indicators', [])

        if malware_family != 'unknown':
            summary = f"{malware_family.upper()} 패밀리 악성코드"
        elif threat_category != 'unknown':
            category_names = {
                'banking_trojan': '뱅킹 트로이목마',
                'infostealer': '정보 탈취 악성코드',
                'financial_malware': '금융 악성코드',
                'ransomware': '랜섬웨어',
                'downloader': '다운로더',
                'backdoor': '백도어',
                'generic_malware': '일반 악성코드'
            }
            summary = category_names.get(threat_category, '알 수 없는 위협')
        else:
            summary = "의심 활동 탐지"

        if risk_indicators:
            summary += f" ({', '.join(risk_indicators[:3])})"  # 최대 3개까지 표시

        return summary


if __name__ == "__main__":
    extractor = FeatureExtractor()

    if os.path.exists("sample/mecro"):
        files = [os.path.join("sample/mecro", f) for f in os.listdir("sample/mecro")][:3]
        if files:
            for file_path in files:
                features = extractor.extract_file_features(file_path)
                threat_summary = extractor.get_threat_summary(features)
                print(f"{os.path.basename(file_path)}: {threat_summary}")