# main.py

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import threading
import time
import requests
from tkinter import messagebox

from PyPDF2 import PdfReader
from PyPDF2.generic import IndirectObject
from utils.office_macro import remove_macro, is_macro_present
from utils.pdf_sanitizer import sanitize_pdf, find_javascript_keys
from utils.hwp_sanitizer import sanitize_hwp
from utils.model_manager import get_model_manager
from utils.malware_classifier import MalwareClassifier
from utils.virustotal_checker import create_virustotal_checker
from dotenv import load_dotenv
load_dotenv()                      # .env 파일 읽기
import config           # AWS/RDS 설정값
from utils import aws_helper       # S3 다운로드/업로드 래퍼
from utils.model_trainer import ModelTrainer
from utils.aws_helper import get_s3_model_info

def bootstrap_models():
    """
    첫 실행 때 S3에서 모델 & 스케일러를 내려받는다.
    이미 로컬에 있으면 생략.
    """
    targets = {
        "models/ensemble_model.pkl": "models/ensemble_model.pkl",
        "models/scaler.pkl":         "models/scaler.pkl",
    }

    if not config.USE_AWS:
        print("[BOOT] USE_AWS=false → S3 동기화 건너뜀")
        return

    for s3_key, local_path in targets.items():
        if not os.path.exists(local_path):
            print(f"[BOOT] S3 → {local_path} 다운로드 시도")
            aws_helper.download(s3_key, local_path)
        else:
            print(f"[BOOT] {local_path} 이미 존재 → 건너뜀")

bootstrap_models()

uploaded_files = []
target_files = []
model_manager = get_model_manager()
malware_classifier = MalwareClassifier()
virustotal_checker = create_virustotal_checker()

def log_append(text):
    """로그에 텍스트 추가"""
    timestamp = time.strftime("[%H:%M:%S] ")
    log_text.insert(tk.END, timestamp + text + "\n")
    log_text.see(tk.END)
    root.update()


def history_append(text):
    """히스토리에 텍스트 추가"""
    timestamp = time.strftime("[%H:%M:%S] ")
    history_text.insert(tk.END, timestamp + text + "\n")
    history_text.see(tk.END)
    root.update()


def clear_logs():
    """로그 초기화"""
    log_text.delete(1.0, tk.END)
    history_text.delete(1.0, tk.END)
    log_append("로그가 초기화되었습니다.")


def classify_malware_type(file_path):
    """악성코드 유형 분류"""
    try:
        malware_type = malware_classifier.classify_malware(file_path)
        return malware_type
    except Exception as e:
        return f"분류 오류: {str(e)}"


def update_model_status():
    """모델 상태 업데이트"""
    if model_manager.is_model_available():
        if model_manager.load_model():
            ai_scan_button.config(state="normal")
        else:
            ai_scan_button.config(state="disabled")
    else:
        ai_scan_button.config(state="disabled")


def upload_files():
    files = filedialog.askopenfilenames(
        filetypes=[("지원 문서 형식", "*.docx *.docm *.xlsx *.xlsm *.pptx *.pptm *.pdf *.hwp *.hwpx *.hwpml")]
    )
    for f in files:
        if f not in uploaded_files:
            uploaded_files.append(f)
            left_listbox.insert(tk.END, os.path.basename(f))

    if files:
        log_append(f"{len(files)}개 파일이 업로드되었습니다.")


def move_to_target():
    selected = left_listbox.curselection()
    moved_count = 0
    for i in selected[::-1]:
        file = uploaded_files[i]
        if file not in target_files:
            target_files.append(file)
            right_listbox.insert(tk.END, os.path.basename(file))
            moved_count += 1
    for i in selected[::-1]:
        left_listbox.delete(i)
        del uploaded_files[i]

    if moved_count > 0:
        log_append(f"{moved_count}개 파일이 분석 대상으로 이동되었습니다.")


def remove_from_target():
    selected = right_listbox.curselection()
    moved_count = 0
    for i in selected[::-1]:
        file = target_files[i]
        uploaded_files.append(file)
        left_listbox.insert(tk.END, os.path.basename(file))
        right_listbox.delete(i)
        del target_files[i]
        moved_count += 1

    if moved_count > 0:
        log_append(f"{moved_count}개 파일이 업로드 목록으로 되돌려졌습니다.")


def scan_for_threats():
    """룰 기반 탐지"""
    if not target_files:
        messagebox.showwarning("경고", "먼저 스캔할 파일을 선택하세요.")
        return

    log_append("=== 룰 기반 악성코드 탐지 시작 ===")

    for file_path in target_files:
        ext = os.path.splitext(file_path)[1].lower()
        file_name = os.path.basename(file_path)

        try:
            log_append(f"[INFO] 문서 분석: {file_name}")

            if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
                if is_macro_present(file_path):
                    log_append("[위험] 매크로 탐지됨 (vbaProject.bin 존재)")
                    history_append(f"{file_name}")
                    history_append(f"  └ 탐지: vbaProject.bin")
                else:
                    log_append("[안전] 매크로 없음")

            elif ext == ".pdf":
                reader = PdfReader(file_path)
                root = reader.trailer.get("/Root", {})
                if isinstance(root, IndirectObject):
                    root = root.get_object()

                found_keys = find_javascript_keys(root)
                if found_keys:
                    log_append(f"[위험] JavaScript 의심 요소 탐지됨")
                    history_append(f"{file_name}")
                    for key in found_keys:
                        history_append(f"  └ 탐지: {key}")
                else:
                    log_append("[안전] JavaScript 없음")

            elif ext in (".hwp", ".hwpx", ".hwpml"):
                with open(file_path, "rb") as f:
                    data = f.read()
                found = []
                for pattern in [b'Shell', b'cmd', b'urlmon', b'http', b'javascript']:
                    if pattern in data:
                        found.append(pattern.decode())
                if found:
                    log_append(f"[위험] 위험 문자열 탐지됨")
                    history_append(f"{file_name}")
                    for s in found:
                        history_append(f"  └ 탐지: {s}")
                else:
                    log_append("[안전] 위험 문자열 없음")
            else:
                log_append("[오류] 지원되지 않는 파일 형식")

        except Exception as e:
            log_append(f"[오류] 처리 중 오류 발생: {str(e)}")

    log_append("=== 룰 기반 스캔 완료 ===")


def ai_scan_threats():
    """AI 모델 + 룰 기반 + VirusTotal 통합 탐지"""
    if not target_files:
        messagebox.showwarning("경고", "먼저 스캔할 파일을 선택하세요.")
        return

    log_text.delete(1.0, tk.END)
    history_text.delete(1.0, tk.END)

    progress_window = tk.Toplevel(root)
    progress_window.title("통합 악성코드 탐지 진행 중...")
    progress_window.geometry("400x120")
    progress_window.resizable(False, False)

    progress_label = tk.Label(progress_window, text="AI + 룰 기반 + VirusTotal 통합 스캔 중...")
    progress_label.pack(pady=10)

    progress_bar = ttk.Progressbar(progress_window, mode='indeterminate')
    progress_bar.pack(pady=10, padx=20, fill='x')
    progress_bar.start()

    try:
        from utils.api_client import APIClient
        api_client = APIClient()
        virustotal_available = bool(api_client.virustotal_key)
    except:
        virustotal_available = False

    def scan_thread():
        try:
            log_text.insert(tk.END, "=== 통합 악성코드 탐지 시작 ===\n")
            if virustotal_available:
                log_text.insert(tk.END, "VirusTotal API 활성화됨\n")
            else:
                log_text.insert(tk.END, "VirusTotal API 비활성화 (의심 파일만 AI+룰 기반 검사)\n")
            log_text.insert(tk.END, "=" * 50 + "\n")

            for i, file_path in enumerate(target_files):
                file_name = os.path.basename(file_path)
                log_text.insert(tk.END, f"\n[{i + 1}/{len(target_files)}] 1차 분석: {file_name}\n")
                root.update()

                is_suspicious = False
                ai_result = None
                rule_threats = []

                # AI 모델 예측
                if model_manager.is_model_available() and model_manager.load_model():
                    ai_result = model_manager.predict_file(file_path)

                    if "error" not in ai_result:
                        prediction = ai_result['prediction']
                        confidence = ai_result['confidence']
                        malware_prob = ai_result.get('malware_probability', 0)

                        log_text.insert(tk.END, f"[AI] 예측: {prediction} (신뢰도: {confidence:.3f})\n")

                        if prediction == "악성":
                            is_suspicious = True
                            log_text.insert(tk.END, f"      └ 악성 확률: {malware_prob:.3f}\n")
                    else:
                        log_text.insert(tk.END, f"[AI] 오류: {ai_result['error']}\n")

                # 룰 기반 탐지
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

                    if rule_threats:
                        log_text.insert(tk.END, f"[룰] 탐지: {', '.join(rule_threats)}\n")

                except Exception as e:
                    log_text.insert(tk.END, f"[룰] 검사 오류: {str(e)}\n")

                # VirusTotal 재검증 (의심 파일만)
                virustotal_result = None
                final_verdict = "정상"

                if is_suspicious and virustotal_available:
                    log_text.insert(tk.END, f"[VT] 의심 파일 → VirusTotal 재검증 중...\n")
                    root.update()

                    try:
                        virustotal_result = api_client.check_file_with_virustotal(file_path)

                        if "error" not in virustotal_result:
                            malicious = virustotal_result.get('malicious', 0)
                            suspicious_vt = virustotal_result.get('suspicious', 0)
                            total = virustotal_result.get('total', 0)

                            if total > 0:
                                detection_rate = (malicious + suspicious_vt) / total
                                log_text.insert(tk.END,
                                                f"[VT] 탐지율: {malicious + suspicious_vt}/{total} ({detection_rate:.1%})\n")

                                if malicious >= 5:
                                    final_verdict = "고위험 악성"
                                elif malicious >= 2 or suspicious_vt >= 3:
                                    final_verdict = "의심"
                                else:
                                    final_verdict = "낮은 위험"
                            else:
                                log_text.insert(tk.END, f"[VT] 데이터베이스에 없는 파일\n")
                                final_verdict = "미확인"
                        else:
                            log_text.insert(tk.END, f"[VT] 검사 실패: {virustotal_result['error']}\n")
                            final_verdict = "AI+룰 기반 의심"

                    except Exception as vt_error:
                        log_text.insert(tk.END, f"[VT] 오류: {str(vt_error)}\n")
                        final_verdict = "AI+룰 기반 의심"

                elif is_suspicious and not virustotal_available:
                    final_verdict = "AI+룰 기반 의심"

                # 최종 결과 출력
                if final_verdict != "정상":
                    if final_verdict == "고위험 악성":
                        log_text.insert(tk.END, f"[최종] 고위험 악성 파일 확인!\n")
                        history_text.insert(tk.END, f"{file_name} (고위험 악성)\n")
                    elif final_verdict == "의심":
                        log_text.insert(tk.END, f"[최종] 의심스러운 파일\n")
                        history_text.insert(tk.END, f"{file_name} (의심)\n")
                    else:
                        log_text.insert(tk.END, f"[최종] 주의 필요 ({final_verdict})\n")
                        history_text.insert(tk.END, f"{file_name} ({final_verdict})\n")

                    # 상세 탐지 내역
                    if ai_result and ai_result.get('prediction') == "악성":
                        history_text.insert(tk.END, f"  └ AI: 악성 예측 ({ai_result.get('confidence', 0):.3f})\n")

                    if rule_threats:
                        history_text.insert(tk.END, f"  └ 룰: {', '.join(rule_threats)}\n")

                    if virustotal_result and "error" not in virustotal_result:
                        malicious = virustotal_result.get('malicious', 0)
                        total = virustotal_result.get('total', 0)
                        if total > 0:
                            history_text.insert(tk.END, f"  └ VT: {malicious}/{total}개 엔진 탐지\n")

                else:
                    log_text.insert(tk.END, f"[최종] 안전한 파일\n")

                log_text.insert(tk.END, "-" * 50 + "\n")
                log_text.see(tk.END)
                root.update()

                if is_suspicious and virustotal_available:
                    import time
                    time.sleep(1)

            log_text.insert(tk.END, "\n=== 통합 스캔 완료 ===\n")

        except Exception as e:
            log_text.insert(tk.END, f"\n[오류] 스캔 중 오류: {str(e)}\n")
        finally:
            progress_bar.stop()
            progress_window.destroy()

    thread = threading.Thread(target=scan_thread)
    thread.daemon = True
    thread.start()


def virustotal_scan():
    """VirusTotal을 이용한 파일 검사"""
    if not target_files:
        messagebox.showwarning("경고", "먼저 검사할 파일을 선택하세요.")
        return

    if not virustotal_checker.is_available():
        messagebox.showerror("오류", "VirusTotal API 키가 설정되지 않았습니다.\n.env 파일에 VIRUSTOTAL_API_KEY를 설정해주세요.")
        return

    progress_window = tk.Toplevel(root)
    progress_window.title("VirusTotal 검사 중...")
    progress_window.geometry("450x120")
    progress_window.resizable(False, False)

    progress_label = tk.Label(progress_window, text="VirusTotal에서 파일을 검사하고 있습니다...")
    progress_label.pack(pady=10)

    progress_bar = ttk.Progressbar(progress_window, mode='indeterminate')
    progress_bar.pack(pady=10, padx=20, fill='x')
    progress_bar.start()

    def scan_thread():
        try:
            log_append("=== VirusTotal 검사 시작 ===")

            for i, file_path in enumerate(target_files):
                file_name = os.path.basename(file_path)
                log_append(f"[{i + 1}/{len(target_files)}] VirusTotal 검사 중: {file_name}")

                result = virustotal_checker.comprehensive_check(file_path)
                vt_message = virustotal_checker.format_result_message(result)

                log_append(f"  └ {vt_message}")

                if "error" not in result:
                    verdict = result.get("verdict", "알 수 없음")

                    if verdict == "악성":
                        history_append(f"{file_name} (VirusTotal: 악성 탐지)")
                        malicious = result.get("malicious", 0)
                        total = result.get("total_engines", 0)
                        history_append(f"  └ 탐지 엔진: {malicious}/{total}")

                    elif verdict == "의심":
                        history_append(f"{file_name} (VirusTotal: 의심스러움)")

                if i < len(target_files) - 1:
                    time.sleep(1)

            log_append("=== VirusTotal 검사 완료 ===")

        except Exception as e:
            log_append(f"[오류] VirusTotal 검사 중 오류: {str(e)}")
        finally:
            progress_bar.stop()
            progress_window.destroy()

    thread = threading.Thread(target=scan_thread)
    thread.daemon = True
    thread.start()


def start_sanitization():
    if not target_files:
        messagebox.showwarning("경고", "먼저 무해화할 파일을 선택하세요.")
        return

    log_append("=== 문서 무해화 시작 ===")

    for file_path in target_files:
        ext = os.path.splitext(file_path)[1].lower()
        file_name = os.path.basename(file_path)

        try:
            log_append(f"[INFO] 문서 처리: {file_name}")

            if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
                clean_file, removed = remove_macro(file_path)
                if removed:
                    log_append(f"[완료] 매크로 제거됨: → {os.path.basename(clean_file)}")
                    history_append(f"{file_name}")
                    history_append(f"  └ 제거: vbaProject.bin")
                else:
                    log_append("[완료] 매크로 없음")

            elif ext == ".pdf":
                clean_file, removed_keys = sanitize_pdf(file_path)
                if removed_keys:
                    log_append(f"[완료] JavaScript 제거됨: → {os.path.basename(clean_file)}")
                    history_append(f"{file_name}")
                    for key in removed_keys:
                        history_append(f"  └ 제거: {key}")
                else:
                    log_append("[완료] JavaScript 없음")

            elif ext in (".hwp", ".hwpx", ".hwpml"):
                clean_file, removed_strings = sanitize_hwp(file_path)
                if removed_strings:
                    log_append(f"[완료] 문자열 제거됨: → {os.path.basename(clean_file)}")
                    history_append(f"{file_name}")
                    for s in removed_strings:
                        history_append(f"  └ 제거: {s}")
                else:
                    log_append("[완료] 위험 문자열 없음")
            else:
                log_append("[오류] 지원되지 않는 파일 형식입니다")

        except Exception as e:
            log_append(f"[오류] 처리 중 오류 발생: {str(e)}")

    log_append("=== 무해화 완료 ===")
    messagebox.showinfo("완료", "문서 무해화가 완료되었습니다!\n정리된 파일은 sample/clear 폴더에 저장되었습니다.")


def train_model():
    """모델 재훈련"""
    response = messagebox.askyesno("모델 훈련",
                                   "새로운 AI 모델을 훈련하시겠습니까?\n"
                                   "이 작업은 시간이 오래 걸릴 수 있습니다.")
    if not response:
        return

    progress_window = tk.Toplevel(root)
    progress_window.title("모델 훈련 중...")
    progress_window.geometry("400x150")
    progress_window.resizable(False, False)

    progress_label = tk.Label(progress_window, text="AI 모델을 훈련하고 있습니다...\n잠시만 기다려주세요.")
    progress_label.pack(pady=20)

    progress_bar = ttk.Progressbar(progress_window, mode='indeterminate')
    progress_bar.pack(pady=10, padx=20, fill='x')
    progress_bar.start()

    def training_thread():
        try:
            log_append("모델 훈련을 시작합니다...")
            success = model_manager.train_new_model()
            progress_bar.stop()
            progress_window.destroy()

            if success:
                messagebox.showinfo("성공", "AI 모델 훈련이 완료되었습니다!")
                log_append("AI 모델 훈련 완료!")
                update_model_status()
            else:
                messagebox.showerror("실패", "AI 모델 훈련에 실패했습니다.")
                log_append("AI 모델 훈련 실패")
        except Exception as e:
            progress_bar.stop()
            progress_window.destroy()
            messagebox.showerror("오류", f"훈련 중 오류가 발생했습니다: {str(e)}")
            log_append(f"훈련 오류: {str(e)}")

    thread = threading.Thread(target=training_thread)
    thread.daemon = True
    thread.start()

def retrain_model_remotely():
    try:
        response = requests.post("http://localhost:8000/train", timeout=600)
        if response.status_code == 200:
            data = response.json()
            messagebox.showinfo("재훈련 완료", f"""
정확도: {data['accuracy']:.3f}
악성 샘플: {data['malware_samples']}개
정상 샘플: {data['clean_samples']}개
총 샘플: {data['total_samples']}개
훈련 시각: {data['trained_at']}
버전: {data['model_version']}
""")
        else:
            messagebox.showerror("실패", f"학습 실패: {response.status_code}")
    except Exception as e:
        messagebox.showerror("에러", f"연결 실패:\n{str(e)}")


def show_model_info():
    info_text = ""

    if config.USE_AWS:
        s3_info = get_s3_model_info("models/ensemble_model.pkl")

        if "error" not in s3_info:
            info_text += f"""=== S3 모델 메타 정보 ===
업로드 시각: {s3_info['last_modified']}
SHA256 해시: {s3_info['sha256'][:32]}...
S3 모델 크기: {s3_info['size_mb']} MB
"""

            meta = s3_info.get("meta", {})
            if meta and "error" not in meta:
                info_text += f"""\n=== S3 모델 학습 정보 ===
악성 샘플: {meta['malware_samples']}개
정상 샘플: {meta['clean_samples']}개
총 샘플: {meta['total_samples']}개
정확도: {meta['accuracy']:.3f}
훈련 시각: {meta['trained_at']}
모델 버전: {meta['model_version']}
"""
            else:
                info_text += "\n[S3] model_meta.json 없음 또는 파싱 실패"
        else:
            info_text += f"\n[S3 오류] {s3_info['error']}"

    else:
        info_text = "USE_AWS=false → 로컬 메타 조회는 제거됨"

    messagebox.showinfo("AI 모델 정보", info_text)




# GUI 구성
root = tk.Tk()
root.title("문서형 악성코드 무해화 시스템 v2.2")
root.geometry("1200x800")
root.resizable(False, False)

# Notebook(탭) 생성
notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True)

# ① 무해화/검사 탭
tab_proc = ttk.Frame(notebook)
notebook.add(tab_proc, text="무해화 처리")

# ② 모델 관리 탭
tab_model = ttk.Frame(notebook)
notebook.add(tab_model, text="모델 정보")

# ───── 탭 ① : 무해화 처리 UI ─────
# (기존 위젯들을 tab_proc 안에 배치)

# 색상 상수
APP_BG_COLOR = "#303030"
TEXT_AREA_BG_COLOR = "#252525"
TEXT_FG_COLOR = "#E0E0E0"
CURSOR_COLOR = "#FFFFFF"
SCROLLBAR_TROUGH_COLOR = APP_BG_COLOR
SCROLLBAR_BG_COLOR = "#505050"

style = ttk.Style()
style.configure("Dark.Vertical.TScrollbar",
                background=SCROLLBAR_BG_COLOR,
                troughcolor=SCROLLBAR_TROUGH_COLOR,
                arrowcolor=TEXT_FG_COLOR,
                relief=tk.FLAT)

# 상단 파일 리스트
top_frame = tk.Frame(tab_proc)
top_frame.pack(pady=15)

left_frame = tk.Frame(top_frame)
left_frame.pack(side=tk.LEFT, padx=20)

tk.Label(left_frame, text="업로드된 문서").pack()
left_listbox = tk.Listbox(left_frame, width=40, height=15)
left_listbox.pack()

center_frame = tk.Frame(top_frame)
center_frame.pack(side=tk.LEFT, padx=10)

tk.Button(center_frame, text="→", width=5, command=lambda: move_to_target()).pack(pady=10)

right_frame = tk.Frame(top_frame)
right_frame.pack(side=tk.LEFT, padx=20)

tk.Label(right_frame, text="분석/무해화 대상 문서").pack()
right_listbox = tk.Listbox(right_frame, width=40, height=15)
right_listbox.pack()

# 중단 버튼들
button_frame = tk.Frame(tab_proc)
button_frame.pack(pady=10)

ai_scan_button = tk.Button(button_frame, text="악성코드 검사", width=15, command=ai_scan_threats,
                           bg="#4CAF50", fg="black")

tk.Button(button_frame, text="문서 업로드", width=15, command=upload_files).pack(side=tk.LEFT, padx=5)
ai_scan_button.pack(side=tk.LEFT, padx=5)

tk.Button(button_frame, text="무해화 및 저장", width=15, command=start_sanitization).pack(side=tk.LEFT, padx=5)

# 로그 초기화 버튼
btn_clear = tk.Button(button_frame, text="로그 초기화", bg="#FF6B6B", command=clear_logs)
btn_clear.pack(side=tk.LEFT, padx=5)  # ← 다른 버튼들과 동일하게 pack 사용

# 로그 영역
log_label = tk.Label(tab_proc, text="시스템 로그", bg=APP_BG_COLOR, fg=TEXT_FG_COLOR)
log_label.pack()

log_frame = tk.Frame(tab_proc, bg=TEXT_AREA_BG_COLOR)
log_frame.pack(pady=5, fill=tk.X, padx=20)

log_text = tk.Text(log_frame, height=8, width=95, bg=TEXT_AREA_BG_COLOR, fg=TEXT_FG_COLOR,
                   insertbackground=CURSOR_COLOR, relief=tk.FLAT, borderwidth=0)
log_scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=log_text.yview,
                              style="Dark.Vertical.TScrollbar")
log_text.configure(yscrollcommand=log_scrollbar.set)
log_text.pack(side="left", fill=tk.BOTH, expand=True)
log_scrollbar.pack(side="right", fill="y")

# 히스토리 영역
history_label = tk.Label(tab_proc, text="탐지/무해화 내역 히스토리", bg=APP_BG_COLOR, fg=TEXT_FG_COLOR)
history_label.pack()

history_frame = tk.Frame(tab_proc, bg=TEXT_AREA_BG_COLOR)
history_frame.pack(pady=5, fill=tk.X, padx=20)

history_text = tk.Text(history_frame, height=8, width=95, wrap=tk.WORD, bg=TEXT_AREA_BG_COLOR,
                       fg=TEXT_FG_COLOR, insertbackground=CURSOR_COLOR, relief=tk.FLAT, borderwidth=0)
history_scrollbar = ttk.Scrollbar(history_frame, orient="vertical", command=history_text.yview,
                                  style="Dark.Vertical.TScrollbar")
history_text.configure(yscrollcommand=history_scrollbar.set)
history_text.pack(side="left", fill=tk.BOTH, expand=True)
history_scrollbar.pack(side="right", fill="y")

# ───── 탭 ② : 모델 정보 UI ─────
status_frame = tk.Frame(tab_model)
status_frame.pack(pady=20)

btn_info     = tk.Button(status_frame, text="모델 정보", command=show_model_info)
btn_retrain  = tk.Button(status_frame, text="모델 재훈련", command=retrain_model_remotely)

btn_info.grid(row=0, column=0, padx=10)
btn_retrain.grid(row=0, column=1, padx=10)

# ────────────────────── 기타 초기화 ─────────────────────
root.after(500, lambda: log_append("문서형 악성코드 무해화 시스템 v2.2 시작"))
root.after(1000, lambda: update_model_status())

root.mainloop()
