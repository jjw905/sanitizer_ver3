# main.py - 문서형 악성코드 무해화 시스템 GUI

import os
import sys
import time
import threading
import subprocess
import platform
import customtkinter as ctk
from tkinter import messagebox, filedialog
from PyPDF2 import PdfReader
from PyPDF2.generic import IndirectObject

# 유틸리티 임포트
from utils.model_manager import get_model_manager
from utils.malware_classifier import MalwareClassifier
from utils.virustotal_checker import create_virustotal_checker
from utils.office_macro import is_macro_present, remove_macro
from utils.pdf_sanitizer import sanitize_pdf, find_javascript_keys
from utils.hwp_sanitizer import sanitize_hwp
import config


class EmbeddedServer:
    """내장 서버 관리"""

    def __init__(self, gui_instance):
        self.gui = gui_instance
        self.server_process = None
        self.server_running = False

    def start_server(self):
        """내장 서버 시작"""
        try:
            import uvicorn
            from retrain_server import app

            # 별도 스레드에서 서버 실행
            def run_server():
                try:
                    self.server_running = True
                    self.gui.log_append("내장 서버 시작 중...")

                    uvicorn.run(
                        app,
                        host="127.0.0.1",
                        port=int(config.SERVER_PORT),
                        log_level="error"
                    )
                except Exception as e:
                    self.gui.log_append(f"내장 서버 시작 실패: {e}")
                    self.server_running = False

            server_thread = threading.Thread(target=run_server, daemon=True)
            server_thread.start()

            # 서버 시작 대기
            time.sleep(2)

            if self.server_running:
                self.gui.log_append("내장 서버 시작 완료")
                self.gui.server_connected = True

        except ImportError:
            self.gui.log_append("서버 모듈을 찾을 수 없습니다")
        except Exception as e:
            self.gui.log_append(f"서버 시작 오류: {e}")

    def stop_server(self):
        """서버 중지"""
        self.server_running = False
        if self.server_process:
            self.server_process.terminate()


class SanitizerGUI:
    """문서형 악성코드 무해화 시스템 GUI"""

    def __init__(self):
        # 메인 윈도우 설정
        self.root = ctk.CTk()
        self.root.title("문서형 악성코드 무해화 시스템 v2.2")
        self.root.geometry("1200x800")
        self.root.resizable(False, False)

        # 전역 변수 초기화
        self.uploaded_files = []
        self.model_manager = get_model_manager()
        self.malware_classifier = MalwareClassifier()
        self.virustotal_checker = create_virustotal_checker()
        self.sanitization_history = []
        self.server_connected = False
        self.last_scan_results = []

        # 내장 서버 초기화
        self.embedded_server = EmbeddedServer(self)

        # UI 생성
        self.create_ui()

        # 시스템 초기화
        self.log_append("문서형 악성코드 무해화 시스템 v2.2 시작")
        self.root.after(1000, self.initialize_system)

    def create_ui(self):
        """UI 구성"""
        # 메인 프레임
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 상단 버튼 프레임
        button_frame = ctk.CTkFrame(main_frame)
        button_frame.pack(fill="x", padx=10, pady=5)

        # 파일 업로드 버튼
        self.upload_btn = ctk.CTkButton(
            button_frame,
            text="파일 선택",
            command=self.upload_files,
            width=120,
            height=35
        )
        self.upload_btn.pack(side="left", padx=5, pady=5)

        # AI 스캔 버튼
        self.scan_btn = ctk.CTkButton(
            button_frame,
            text="AI 스캔",
            command=self.ai_scan_threats,
            width=120,
            height=35
        )
        self.scan_btn.pack(side="left", padx=5, pady=5)

        # 무해화 버튼
        self.sanitize_btn = ctk.CTkButton(
            button_frame,
            text="무해화",
            command=self.sanitize_files,
            width=120,
            height=35
        )
        self.sanitize_btn.pack(side="left", padx=5, pady=5)

        # 모델 훈련 버튼
        self.train_btn = ctk.CTkButton(
            button_frame,
            text="모델 훈련",
            command=self.train_model,
            width=120,
            height=35
        )
        self.train_btn.pack(side="left", padx=5, pady=5)

        # 내역 다운로드 버튼
        self.download_btn = ctk.CTkButton(
            button_frame,
            text="내역 다운로드",
            command=self.download_sanitization_history,
            width=120,
            height=35
        )
        self.download_btn.pack(side="left", padx=5, pady=5)

        # 상태 표시 레이블
        self.status_label = ctk.CTkLabel(
            button_frame,
            text="준비",
            width=200
        )
        self.status_label.pack(side="right", padx=10, pady=5)

        # 중간 프레임 (로그와 히스토리)
        content_frame = ctk.CTkFrame(main_frame)
        content_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # 로그 영역
        log_frame = ctk.CTkFrame(content_frame)
        log_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        log_label = ctk.CTkLabel(log_frame, text="실행 로그", font=("Arial", 14, "bold"))
        log_label.pack(pady=5)

        self.log_text = ctk.CTkTextbox(log_frame, height=500, width=600)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=5)

        # 히스토리 영역
        history_frame = ctk.CTkFrame(content_frame)
        history_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        history_label = ctk.CTkLabel(history_frame, text="처리 내역", font=("Arial", 14, "bold"))
        history_label.pack(pady=5)

        self.history_text = ctk.CTkTextbox(history_frame, height=500, width=400)
        self.history_text.pack(fill="both", expand=True, padx=10, pady=5)

    def log_append(self, message):
        """로그 메시지 추가"""
        timestamp = time.strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"

        self.log_text.insert("end", formatted_message)
        self.log_text.see("end")
        self.root.update()

    def create_progress_window(self, title, message):
        """진행률 창 생성"""
        progress_window = ctk.CTkToplevel(self.root)
        progress_window.title(title)
        progress_window.geometry("400x150")
        progress_window.transient(self.root)
        progress_window.grab_set()

        # 중앙 정렬
        progress_window.update_idletasks()
        x = (progress_window.winfo_screenwidth() // 2) - (400 // 2)
        y = (progress_window.winfo_screenheight() // 2) - (150 // 2)
        progress_window.geometry(f"400x150+{x}+{y}")

        message_label = ctk.CTkLabel(progress_window, text=message, wraplength=350)
        message_label.pack(pady=20)

        progress_bar = ctk.CTkProgressBar(progress_window, width=300)
        progress_bar.pack(pady=10)
        progress_bar.configure(mode="indeterminate")
        progress_bar.start()

        return progress_window, progress_bar

    def upload_files(self):
        """파일 업로드"""
        file_paths = filedialog.askopenfilenames(
            title="분석할 파일을 선택하세요",
            filetypes=[
                ("지원 문서", "*.pdf *.docx *.docm *.xlsx *.xlsm *.pptx *.pptm *.hwp *.hwpx"),
                ("PDF 파일", "*.pdf"),
                ("Word 문서", "*.docx *.docm"),
                ("Excel 문서", "*.xlsx *.xlsm"),
                ("PowerPoint 문서", "*.pptx *.pptm"),
                ("한글 문서", "*.hwp *.hwpx"),
                ("모든 파일", "*.*")
            ]
        )

        if file_paths:
            self.uploaded_files = list(file_paths)
            self.log_append(f"{len(file_paths)}개 파일 선택됨")

            for file_path in file_paths:
                self.log_append(f"  - {os.path.basename(file_path)}")

            # 파일 업로드 후 자동으로 스캔 실행
            self.root.after(500, self.ai_scan_threats)

    def initialize_system(self):
        """시스템 초기화"""

        def init_thread():
            try:
                # 내장 서버 시작
                self.embedded_server.start_server()

                # 모델 상태 확인
                if self.model_manager.is_model_available():
                    if self.model_manager.load_model():
                        self.log_append("AI 모델 로드 완료")
                    else:
                        self.log_append("AI 모델 로드 실패")
                else:
                    self.log_append("AI 모델이 없습니다. 모델 훈련을 실행하세요.")

                # API 상태 확인
                try:
                    from utils.api_client import APIClient
                    api_client = APIClient()

                    if api_client.test_malware_bazaar_connection():
                        self.log_append("MalwareBazaar API 연결 성공")
                    else:
                        self.log_append("MalwareBazaar API 연결 실패")

                    if api_client.test_virustotal_connection():
                        self.log_append("VirusTotal API 연결 성공")
                    else:
                        self.log_append("VirusTotal API 연결 실패")

                except Exception as api_error:
                    self.log_append(f"API 연결 확인 중 오류: {api_error}")

                self.status_label.configure(text="시스템 준비 완료")

            except Exception as e:
                self.log_append(f"시스템 초기화 오류: {e}")

        init_thread = threading.Thread(target=init_thread, daemon=True)
        init_thread.start()

    def ai_scan_threats(self):
        """AI 모델 + 룰 기반 + VirusTotal 통합 탐지"""
        if not self.uploaded_files:
            messagebox.showwarning("경고", "먼저 스캔할 파일을 선택하세요.")
            return

        self.log_text.delete("1.0", "end")
        self.history_text.delete("1.0", "end")

        progress_window, progress_bar = self.create_progress_window(
            "통합 악성코드 탐지",
            "AI + 룰 기반 + VirusTotal 통합 스캔 중...\n잠시만 기다려주세요."
        )

        try:
            from utils.api_client import APIClient
            api_client = APIClient()
            virustotal_available = bool(api_client.virustotal_key)
        except:
            virustotal_available = False

        def scan_thread():
            try:
                self.log_text.insert("end", "=== 통합 악성코드 탐지 시작 ===\n")
                if virustotal_available:
                    self.log_text.insert("end", "VirusTotal API 활성화됨\n")
                else:
                    self.log_text.insert("end", "VirusTotal API 비활성화 (의심 파일만 AI+룰 기반 검사)\n")
                self.log_text.insert("end", "=" * 50 + "\n")

                # 검사 결과 저장용
                scan_results = []

                for i, file_path in enumerate(self.uploaded_files):
                    file_name = os.path.basename(file_path)
                    self.log_text.insert("end", f"\n[{i + 1}/{len(self.uploaded_files)}] 1차 분석: {file_name}\n")
                    self.root.update()

                    # 파일별 결과 저장
                    file_result = {
                        'file_name': file_name,
                        'file_path': file_path,
                        'ai_result': None,
                        'rule_threats': [],
                        'virustotal_result': None,
                        'final_verdict': "정상",
                        'scan_timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
                    }

                    is_suspicious = False
                    ai_result = None
                    rule_threats = []

                    # AI 분석
                    if self.model_manager.is_model_available() and self.model_manager.load_model():
                        ai_result = self.model_manager.predict_file(file_path)
                        file_result['ai_result'] = ai_result

                        if "error" not in ai_result:
                            prediction = ai_result['prediction']
                            confidence = ai_result['confidence']
                            malware_prob = ai_result.get('malware_probability', 0)

                            self.log_text.insert("end", f"[AI] 예측: {prediction} (신뢰도: {confidence:.3f})\n")

                            if prediction == "악성":
                                is_suspicious = True
                                self.log_text.insert("end", f"      └ 악성 확률: {malware_prob:.3f}\n")
                        else:
                            self.log_text.insert("end", f"[AI] 오류: {ai_result['error']}\n")

                    # 룰 기반 분석
                    ext = os.path.splitext(file_path)[1].lower()

                    try:
                        if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
                            if is_macro_present(file_path):
                                rule_threats.append("매크로 탐지")
                                is_suspicious = True

                        elif ext == ".pdf":
                            reader = PdfReader(file_path)
                            root_obj = reader.trailer.get("/Root", {})
                            if isinstance(root_obj, IndirectObject):
                                root_obj = root_obj.get_object()

                            found_keys = find_javascript_keys(root_obj)
                            if found_keys:
                                rule_threats.extend(found_keys)
                                is_suspicious = True

                        elif ext in (".hwp", ".hwpx", ".hwpml"):
                            with open(file_path, "rb") as f:
                                data = f.read()
                            for pattern in [b'Shell', b'cmd', b'urlmon', b'http', b'javascript']:
                                if pattern in data:
                                    rule_threats.append(pattern.decode())
                                    is_suspicious = True

                        file_result['rule_threats'] = rule_threats
                        if rule_threats:
                            self.log_text.insert("end", f"[룰] 탐지: {', '.join(rule_threats)}\n")

                    except Exception as e:
                        self.log_text.insert("end", f"[룰] 검사 오류: {str(e)}\n")

                    # VirusTotal 검증
                    virustotal_result = None
                    final_verdict = "정상"

                    if is_suspicious and virustotal_available:
                        self.log_text.insert("end", f"[VT] 의심 파일 → VirusTotal 재검증 중...\n")
                        self.root.update()

                        try:
                            virustotal_result = api_client.check_file_with_virustotal(file_path)
                            file_result['virustotal_result'] = virustotal_result

                            if "error" not in virustotal_result:
                                malicious = virustotal_result.get('malicious', 0)
                                suspicious_vt = virustotal_result.get('suspicious', 0)
                                total = virustotal_result.get('total', 0)

                                if total > 0:
                                    detection_rate = (malicious + suspicious_vt) / total
                                    self.log_text.insert("end",
                                                         f"[VT] 탐지율: {malicious + suspicious_vt}/{total} ({detection_rate:.1%})\n")

                                    if malicious >= 5:
                                        final_verdict = "고위험 악성"
                                    elif malicious >= 2 or suspicious_vt >= 3:
                                        final_verdict = "의심"
                                    else:
                                        final_verdict = "낮은 위험"
                                else:
                                    self.log_text.insert("end", f"[VT] 데이터베이스에 없는 파일\n")
                                    final_verdict = "미확인"
                            else:
                                self.log_text.insert("end", f"[VT] 검사 실패: {virustotal_result['error']}\n")
                                final_verdict = "AI+룰 기반 의심"

                        except Exception as vt_error:
                            self.log_text.insert("end", f"[VT] 오류: {str(vt_error)}\n")
                            final_verdict = "AI+룰 기반 의심"

                    elif is_suspicious and not virustotal_available:
                        final_verdict = "AI+룰 기반 의심"

                    file_result['final_verdict'] = final_verdict

                    # 결과 정리
                    if final_verdict != "정상":
                        if final_verdict == "고위험 악성":
                            self.log_text.insert("end", f"[최종] 고위험 악성 파일 확인!\n")
                            self.history_text.insert("end", f"{file_name} (고위험 악성)\n")
                        elif final_verdict == "의심":
                            self.log_text.insert("end", f"[최종] 의심스러운 파일\n")
                            self.history_text.insert("end", f"{file_name} (의심)\n")
                        else:
                            self.log_text.insert("end", f"[최종] 주의 필요 ({final_verdict})\n")
                            self.history_text.insert("end", f"{file_name} ({final_verdict})\n")

                        if ai_result and ai_result.get('prediction') == "악성":
                            self.history_text.insert("end", f"  └ AI: 악성 예측 ({ai_result.get('confidence', 0):.3f})\n")

                        if rule_threats:
                            self.history_text.insert("end", f"  └ 룰: {', '.join(rule_threats)}\n")

                        if virustotal_result and "error" not in virustotal_result:
                            malicious = virustotal_result.get('malicious', 0)
                            total = virustotal_result.get('total', 0)
                            if total > 0:
                                self.history_text.insert("end", f"  └ VT: {malicious}/{total}개 엔진 탐지\n")

                    else:
                        self.log_text.insert("end", f"[최종] 안전한 파일\n")

                    # 검사 결과 저장
                    scan_results.append(file_result)

                    self.log_text.insert("end", "-" * 50 + "\n")
                    self.log_text.see("end")
                    self.root.update()

                    if is_suspicious and virustotal_available:
                        time.sleep(1)

                # 검사 결과를 클래스 변수에 저장
                self.last_scan_results = scan_results

                self.log_text.insert("end", "\n=== 통합 스캔 완료 ===\n")

            except Exception as e:
                self.log_text.insert("end", f"\n[오류] 스캔 중 오류: {str(e)}\n")
            finally:
                progress_bar.stop()
                progress_window.destroy()

        thread = threading.Thread(target=scan_thread)
        thread.daemon = True
        thread.start()

    def sanitize_files(self):
        """파일 무해화"""
        if not self.uploaded_files:
            messagebox.showwarning("경고", "먼저 무해화할 파일을 선택하세요.")
            return

        progress_window, progress_bar = self.create_progress_window(
            "파일 무해화",
            "선택된 파일들을 무해화 중입니다..."
        )

        def sanitize_thread():
            try:
                self.log_append("=== 파일 무해화 시작 ===")

                for i, file_path in enumerate(self.uploaded_files):
                    file_name = os.path.basename(file_path)
                    ext = os.path.splitext(file_path)[1].lower()

                    self.log_append(f"[{i + 1}/{len(self.uploaded_files)}] {file_name} 무해화 중...")

                    try:
                        removed_elements = []
                        clean_file = None

                        if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
                            clean_file, macro_removed = remove_macro(file_path)
                            if macro_removed:
                                removed_elements.append("매크로")

                        elif ext == ".pdf":
                            clean_file, removed_keys = sanitize_pdf(file_path)
                            if removed_keys:
                                removed_elements.extend(removed_keys)

                        elif ext in (".hwp", ".hwpx", ".hwpml"):
                            clean_file, removed_strings = sanitize_hwp(file_path)
                            if removed_strings:
                                removed_elements.extend(removed_strings)

                        else:
                            self.log_append(f"지원하지 않는 파일 형식: {ext}")
                            continue

                        if clean_file:
                            result_msg = "성공" if removed_elements else "정상 파일 (변경사항 없음)"
                            self.log_append(f"무해화 완료: {os.path.basename(clean_file)}")

                            if removed_elements:
                                self.log_append(f"  제거된 요소: {', '.join(removed_elements)}")

                            # 무해화 이력 저장
                            self.sanitization_history.append({
                                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                                'original_file': file_name,
                                'clean_file': clean_file,
                                'file_type': ext,
                                'result': result_msg,
                                'removed_elements': removed_elements
                            })

                            self.history_text.insert("end", f"무해화: {file_name}\n")
                            if removed_elements:
                                self.history_text.insert("end", f"  제거: {', '.join(removed_elements)}\n")

                        else:
                            self.log_append(f"무해화 실패: {file_name}")

                    except Exception as e:
                        self.log_append(f"무해화 오류 ({file_name}): {str(e)}")

                self.log_append("=== 무해화 완료 ===")
                messagebox.showinfo("완료", "모든 파일의 무해화가 완료되었습니다.")

            except Exception as e:
                self.log_append(f"무해화 중 오류: {str(e)}")
                messagebox.showerror("오류", f"무해화 중 오류가 발생했습니다:\n{str(e)}")
            finally:
                progress_bar.stop()
                progress_window.destroy()

        thread = threading.Thread(target=sanitize_thread)
        thread.daemon = True
        thread.start()

    def train_model(self):
        """모델 훈련"""
        result = messagebox.askyesno(
            "모델 훈련",
            "모델 훈련을 시작하시겠습니까?\n\n"
            "새로운 악성코드 샘플을 수집하고 AI 모델을 훈련합니다.\n"
            "이 과정은 몇 분이 소요될 수 있습니다."
        )

        if not result:
            return

        progress_window, progress_bar = self.create_progress_window(
            "모델 훈련",
            "악성코드 샘플 수집 및 AI 모델 훈련 중...\n시간이 다소 소요될 수 있습니다."
        )

        def train_thread():
            try:
                self.log_append("=== AI 모델 훈련 시작 ===")

                # 내장 서버를 통한 훈련 요청
                if self.server_connected:
                    try:
                        import requests
                        response = requests.post(
                            f"http://localhost:{config.SERVER_PORT}/train",
                            timeout=300
                        )

                        if response.status_code == 200:
                            result_data = response.json()
                            self.log_append("모델 훈련 성공!")
                            self.log_append(f"정확도: {result_data.get('accuracy', 0):.3f}")
                            self.log_append(f"총 샘플: {result_data.get('total_samples', 0)}개")

                            # 모델 다시 로드
                            if self.model_manager.load_model():
                                self.log_append("새 모델 로드 완료")

                        else:
                            self.log_append("모델 훈련 실패")

                    except Exception as server_error:
                        self.log_append(f"서버 훈련 실패: {server_error}")
                        self.log_append("로컬 훈련으로 전환...")

                        # 로컬 훈련 시도
                        from utils.model_trainer import train_model
                        if train_model():
                            self.log_append("로컬 모델 훈련 성공!")
                            if self.model_manager.load_model():
                                self.log_append("새 모델 로드 완료")
                        else:
                            self.log_append("로컬 모델 훈련 실패")

                else:
                    # 서버가 없으면 직접 훈련
                    from utils.model_trainer import train_model
                    if train_model():
                        self.log_append("모델 훈련 성공!")
                        if self.model_manager.load_model():
                            self.log_append("새 모델 로드 완료")
                    else:
                        self.log_append("모델 훈련 실패")

                self.log_append("=== 훈련 완료 ===")

            except Exception as e:
                self.log_append(f"훈련 중 오류: {str(e)}")
            finally:
                progress_bar.stop()
                progress_window.destroy()

        thread = threading.Thread(target=train_thread)
        thread.daemon = True
        thread.start()

    def download_sanitization_history(self):
        """무해화 내역을 txt 파일로 다운로드"""
        if not self.sanitization_history and not hasattr(self, 'last_scan_results'):
            messagebox.showwarning("경고", "다운로드할 무해화 내역이나 검사 결과가 없습니다.")
            return

        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("텍스트 파일", "*.txt"), ("모든 파일", "*.*")],
                title="무해화 및 검사 내역 저장"
            )

            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("=== 문서형 악성코드 탐지 및 무해화 종합 내역 ===\n\n")

                    # 검사 결과 작성
                    if hasattr(self, 'last_scan_results'):
                        f.write("[ 1. 악성코드 검사 결과 ]\n")
                        f.write("=" * 50 + "\n")

                        for result in self.last_scan_results:
                            f.write(f"\n파일명: {result['file_name']}\n")
                            f.write(f"검사 시간: {result['scan_timestamp']}\n")
                            f.write(f"최종 판정: {result['final_verdict']}\n")

                            # AI 결과
                            if result['ai_result'] and "error" not in result['ai_result']:
                                ai = result['ai_result']
                                f.write(f"AI 분석: {ai['prediction']} (신뢰도: {ai['confidence']:.3f})\n")
                                if 'malware_probability' in ai:
                                    f.write(f"  └ 악성 확률: {ai['malware_probability']:.3f}\n")

                            # 룰 기반 결과
                            if result['rule_threats']:
                                f.write(f"룰 탐지: {', '.join(result['rule_threats'])}\n")

                            # VirusTotal 결과
                            if result['virustotal_result'] and "error" not in result['virustotal_result']:
                                vt = result['virustotal_result']
                                malicious = vt.get('malicious', 0)
                                suspicious = vt.get('suspicious', 0)
                                total = vt.get('total', 0)
                                clean = vt.get('clean', 0)

                                f.write(f"VirusTotal 검사:\n")
                                f.write(f"  └ 악성 탐지: {malicious}개 엔진\n")
                                f.write(f"  └ 의심 탐지: {suspicious}개 엔진\n")
                                f.write(f"  └ 안전 판정: {clean}개 엔진\n")
                                f.write(f"  └ 총 검사 엔진: {total}개\n")

                                if total > 0:
                                    detection_rate = (malicious + suspicious) / total * 100
                                    f.write(f"  └ 탐지율: {detection_rate:.1f}%\n")

                            f.write("-" * 30 + "\n")

                    # 무해화 내역 작성
                    if self.sanitization_history:
                        f.write(f"\n[ 2. 무해화 처리 내역 ]\n")
                        f.write("=" * 50 + "\n")

                        for entry in self.sanitization_history:
                            f.write(f"\n처리 시간: {entry['timestamp']}\n")
                            f.write(f"원본 파일: {entry['original_file']}\n")
                            f.write(f"파일 유형: {entry['file_type']}\n")
                            f.write(f"무해화 결과: {entry['result']}\n")
                            f.write(f"저장 위치: {entry['clean_file']}\n")
                            f.write(f"제거된 요소: {', '.join(entry['removed_elements'])}\n")

                            # 해당 파일의 검사 결과도 함께 표시
                            if hasattr(self, 'last_scan_results'):
                                matching_result = None
                                for scan_result in self.last_scan_results:
                                    if scan_result['file_name'] == entry['original_file']:
                                        matching_result = scan_result
                                        break

                                if matching_result and matching_result['virustotal_result']:
                                    vt = matching_result['virustotal_result']
                                    if "error" not in vt:
                                        f.write(
                                            f"검사 시 VirusTotal 탐지: {vt.get('malicious', 0)}/{vt.get('total', 0)}개 엔진\n")

                            f.write("-" * 30 + "\n")

                    # 요약 정보
                    f.write(f"\n[ 3. 요약 정보 ]\n")
                    f.write("=" * 50 + "\n")

                    if hasattr(self, 'last_scan_results'):
                        total_scanned = len(self.last_scan_results)
                        malicious_detected = sum(1 for r in self.last_scan_results if r['final_verdict'] != "정상")
                        f.write(f"총 검사 파일: {total_scanned}개\n")
                        f.write(f"악성/의심 탐지: {malicious_detected}개\n")
                        f.write(f"안전 파일: {total_scanned - malicious_detected}개\n")

                    if self.sanitization_history:
                        f.write(f"무해화 처리: {len(self.sanitization_history)}개\n")

                    f.write(f"\n생성 시간: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("문서형 악성코드 무해화 시스템 v2.2\n")

                messagebox.showinfo("완료", f"종합 내역이 저장되었습니다:\n{file_path}")

        except Exception as e:
            messagebox.showerror("오류", f"내역 저장 중 오류가 발생했습니다:\n{str(e)}")

    def run(self):
        """애플리케이션 실행"""
        self.root.mainloop()


def main():
    """메인 실행 함수"""
    try:
        # GUI 실행
        app = SanitizerGUI()
        app.run()
    except Exception as e:
        print(f"애플리케이션 실행 오류: {e}")


if __name__ == "__main__":
    main()