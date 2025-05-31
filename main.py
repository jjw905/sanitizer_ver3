# main.py

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import threading
import time

from PyPDF2 import PdfReader
from PyPDF2.generic import IndirectObject
from utils.office_macro import remove_macro, is_macro_present
from utils.pdf_sanitizer import sanitize_pdf, find_javascript_keys
from utils.hwp_sanitizer import sanitize_hwp
from utils.model_manager import get_model_manager
from utils.malware_classifier import MalwareClassifier
from utils.virustotal_checker import create_virustotal_checker

uploaded_files = []
target_files = []
model_manager = get_model_manager()
malware_classifier = MalwareClassifier()
virustotal_checker = create_virustotal_checker()


def log_append(text):
    """로그에 텍스트 추가 (누적)"""
    timestamp = time.strftime("[%H:%M:%S] ")
    log_text.insert(tk.END, timestamp + text + "\n")
    log_text.see(tk.END)
    root.update()


def history_append(text):
    """히스토리에 텍스트 추가 (누적)"""
    timestamp = time.strftime("[%H:%M:%S] ")
    history_text.insert(tk.END, timestamp + text + "\n")
    history_text.see(tk.END)
    root.update()


def clear_logs():
    """로그 수동 초기화"""
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
    """기존 룰 기반 탐지"""
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
                    log_append("[⚠️] 매크로 탐지됨 (vbaProject.bin 존재)")
                    history_append(f"{file_name}")
                    history_append(f"  └ 탐지: vbaProject.bin")
                else:
                    log_append("[OK] 매크로 없음")

            elif ext == ".pdf":
                reader = PdfReader(file_path)
                root = reader.trailer.get("/Root", {})
                if isinstance(root, IndirectObject):
                    root = root.get_object()

                found_keys = find_javascript_keys(root)
                if found_keys:
                    log_append(f"[⚠️] JavaScript 의심 요소 탐지됨")
                    history_append(f"{file_name}")
                    for key in found_keys:
                        history_append(f"  └ 탐지: {key}")
                else:
                    log_append("[OK] JavaScript 없음")

            elif ext in (".hwp", ".hwpx", ".hwpml"):
                with open(file_path, "rb") as f:
                    data = f.read()
                found = []
                for pattern in [b'Shell', b'cmd', b'urlmon', b'http', b'javascript']:
                    if pattern in data:
                        found.append(pattern.decode())
                if found:
                    log_append(f"[⚠️] 위험 문자열 탐지됨")
                    history_append(f"{file_name}")
                    for s in found:
                        history_append(f"  └ 탐지: {s}")
                else:
                    log_append("[OK] 위험 문자열 없음")
            else:
                log_append("[X] 지원되지 않는 파일 형식")

        except Exception as e:
            log_append(f"[ERROR] 처리 중 오류 발생: {str(e)}")

    log_append("=== 룰 기반 스캔 완료 ===")


def ai_scan_threats():
    """AI 모델 + 룰 기반 + VirusTotal 통합 탐지"""
    if not target_files:
        messagebox.showwarning("경고", "먼저 스캔할 파일을 선택하세요.")
        return

    log_text.delete(1.0, tk.END)
    history_text.delete(1.0, tk.END)

    # 프로그레스 바 표시
    progress_window = tk.Toplevel(root)
    progress_window.title("통합 악성코드 탐지 진행 중...")
    progress_window.geometry("400x120")
    progress_window.resizable(False, False)

    progress_label = tk.Label(progress_window, text="AI + 룰 기반 + VirusTotal 통합 스캔 중...")
    progress_label.pack(pady=10)

    progress_bar = ttk.Progressbar(progress_window, mode='indeterminate')
    progress_bar.pack(pady=10, padx=20, fill='x')
    progress_bar.start()

    # VirusTotal API 클라이언트
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
                log_text.insert(tk.END, "✅ VirusTotal API 활성화됨\n")
            else:
                log_text.insert(tk.END, "⚠️ VirusTotal API 비활성화 (의심 파일만 AI+룰 기반 검사)\n")
            log_text.insert(tk.END, "=" * 50 + "\n")

            suspicious_files = []  # VirusTotal 재검증 대상

            for i, file_path in enumerate(target_files):
                file_name = os.path.basename(file_path)
                log_text.insert(tk.END, f"\n[{i + 1}/{len(target_files)}] 1차 분석: {file_name}\n")
                root.update()

                is_suspicious = False
                ai_result = None
                rule_threats = []

                # === 1단계: AI 모델 예측 ===
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

                # === 2단계: 룰 기반 탐지 ===
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

                # === 3단계: VirusTotal 재검증 (의심 파일만) ===
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

                                # VirusTotal 기준으로 최종 판정 (5개 이상 엔진에서 탐지되면 악성)
                                if malicious >= 5:
                                    final_verdict = "🚨 고위험 악성"
                                elif malicious >= 2 or suspicious_vt >= 3:
                                    final_verdict = "⚠️ 의심"
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

                # === 최종 결과 출력 ===
                if final_verdict != "정상":
                    if final_verdict == "🚨 고위험 악성":
                        log_text.insert(tk.END, f"[최종] 🚨 고위험 악성 파일 확인!\n")
                        history_text.insert(tk.END, f"🚨 {file_name} (고위험 악성)\n")
                    elif final_verdict == "⚠️ 의심":
                        log_text.insert(tk.END, f"[최종] ⚠️ 의심스러운 파일\n")
                        history_text.insert(tk.END, f"⚠️ {file_name} (의심)\n")
                    else:
                        log_text.insert(tk.END, f"[최종] ⚠️ 주의 필요 ({final_verdict})\n")
                        history_text.insert(tk.END, f"⚠️ {file_name} ({final_verdict})\n")

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
                    log_text.insert(tk.END, f"[최종] ✅ 안전한 파일\n")

                log_text.insert(tk.END, "-" * 50 + "\n")
                log_text.see(tk.END)
                root.update()

                # API 제한 대응 (VirusTotal 사용 시)
                if is_suspicious and virustotal_available:
                    import time
                    time.sleep(1)  # 1초 대기

            log_text.insert(tk.END, "\n=== 통합 스캔 완료 ===\n")

        except Exception as e:
            log_text.insert(tk.END, f"\n[ERROR] 스캔 중 오류: {str(e)}\n")
        finally:
            progress_bar.stop()
            progress_window.destroy()

    # 별도 스레드에서 실행
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

                # 히스토리에도 기록
                if "error" not in result:
                    verdict = result.get("verdict", "알 수 없음")

                    if verdict == "악성":
                        history_append(f"🚨 {file_name} (VirusTotal: 악성 탐지)")
                        malicious = result.get("malicious", 0)
                        total = result.get("total_engines", 0)
                        history_append(f"  └ 탐지 엔진: {malicious}/{total}")

                    elif verdict == "의심":
                        history_append(f"⚠️ {file_name} (VirusTotal: 의심스러움)")

                # API 제한 방지를 위한 대기
                if i < len(target_files) - 1:
                    time.sleep(1)

            log_append("=== VirusTotal 검사 완료 ===")

        except Exception as e:
            log_append(f"[ERROR] VirusTotal 검사 중 오류: {str(e)}")
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
                    log_append(f"[✔] 매크로 제거됨: → {os.path.basename(clean_file)}")
                    history_append(f"{file_name}")
                    history_append(f"  └ 제거: vbaProject.bin")
                else:
                    log_append("[OK] 매크로 없음")

            elif ext == ".pdf":
                clean_file, removed_keys = sanitize_pdf(file_path)
                if removed_keys:
                    log_append(f"[✔] JavaScript 제거됨: → {os.path.basename(clean_file)}")
                    history_append(f"{file_name}")
                    for key in removed_keys:
                        history_append(f"  └ 제거: {key}")
                else:
                    log_append("[OK] JavaScript 없음")

            elif ext in (".hwp", ".hwpx", ".hwpml"):
                clean_file, removed_strings = sanitize_hwp(file_path)
                if removed_strings:
                    log_append(f"[✔] 문자열 제거됨: → {os.path.basename(clean_file)}")
                    history_append(f"{file_name}")
                    for s in removed_strings:
                        history_append(f"  └ 제거: {s}")
                else:
                    log_append("[OK] 위험 문자열 없음")
            else:
                log_append("[X] 지원되지 않는 파일 형식입니다")

        except Exception as e:
            log_append(f"[ERROR] 처리 중 오류 발생: {str(e)}")

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
                log_append("✅ AI 모델 훈련 완료!")
                update_model_status()
            else:
                messagebox.showerror("실패", "AI 모델 훈련에 실패했습니다.")
                log_append("❌ AI 모델 훈련 실패")
        except Exception as e:
            progress_bar.stop()
            progress_window.destroy()
            messagebox.showerror("오류", f"훈련 중 오류가 발생했습니다: {str(e)}")
            log_append(f"❌ 훈련 오류: {str(e)}")

    thread = threading.Thread(target=training_thread)
    thread.daemon = True
    thread.start()


def show_model_info():
    """모델 정보 표시"""
    info = model_manager.get_model_info()
    data_status = model_manager.get_training_data_status()

    info_text = f"""=== AI 모델 정보 ===

모델 상태: {'사용 가능' if info['model_available'] else '없음'}
모델 로드: {'완료' if info['model_loaded'] else '대기'}

훈련 데이터:
  - 악성 샘플: {data_status['malware_samples']}개
  - 정상 샘플: {data_status['clean_samples']}개
  - 총 샘플: {data_status['total_samples']}개
  - 데이터 충분성: {'충분' if data_status['sufficient_data'] else '부족'}

"""

    if info['model_available']:
        info_text += f"""모델 파일 크기: {info.get('model_size_mb', 0)} MB
스케일러 크기: {info.get('scaler_size_kb', 0)} KB
"""

    messagebox.showinfo("AI 모델 정보", info_text)


# ────────────── GUI 구성 ──────────────
root = tk.Tk()
root.title("문서형 악성코드 무해화 시스템 v2.2")
root.geometry("1200x800")
root.resizable(False, False)

# ───────── 상단 모델 상태 ─────────
status_frame = tk.Frame(root)
status_frame.pack(pady=5)

tk.Button(status_frame, text="모델 정보", command=show_model_info).pack(side=tk.LEFT, padx=5)
tk.Button(status_frame, text="모델 재훈련", command=train_model).pack(side=tk.LEFT, padx=5)
tk.Button(status_frame, text="로그 초기화", command=clear_logs, bg="#FF6B6B", fg="black").pack(side=tk.LEFT, padx=5)

# ───────── 상단 문서 리스트 ─────────
top_frame = tk.Frame(root)
top_frame.pack(pady=15)

left_frame = tk.Frame(top_frame)
left_frame.pack(side=tk.LEFT, padx=20)
tk.Label(left_frame, text="📂 업로드된 문서").pack()
left_listbox = tk.Listbox(left_frame, width=40, height=15)
left_listbox.pack()

center_frame = tk.Frame(top_frame)
center_frame.pack(side=tk.LEFT, padx=10)
tk.Button(center_frame, text="→", width=5, command=move_to_target).pack(pady=10)
tk.Button(center_frame, text="←", width=5, command=remove_from_target).pack(pady=10)

right_frame = tk.Frame(top_frame)
right_frame.pack(side=tk.LEFT, padx=20)
tk.Label(right_frame, text="🛡 분석/무해화 대상 문서").pack()
right_listbox = tk.Listbox(right_frame, width=40, height=15)
right_listbox.pack()

# ───────── 중단 버튼들 ─────────
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

tk.Button(button_frame, text="문서 업로드", width=15, command=upload_files).pack(side=tk.LEFT, padx=5)

ai_scan_button = tk.Button(button_frame, text="악성코드 검사", width=15, command=ai_scan_threats,
                           bg="#4CAF50", fg="black", font=("Arial", 9, "bold"))
ai_scan_button.pack(side=tk.LEFT, padx=5)

tk.Button(button_frame, text="무해화 및 저장", width=15, command=start_sanitization).pack(side=tk.LEFT, padx=5)

# ───────── 로그 출력 영역 ─────────
log_label = tk.Label(root, text="📄 시스템 로그")
log_label.pack()
log_frame = tk.Frame(root)
log_frame.pack(pady=5)

log_text = tk.Text(log_frame, height=8, width=95)
log_scrollbar = tk.Scrollbar(log_frame, orient="vertical", command=log_text.yview)
log_text.configure(yscrollcommand=log_scrollbar.set)
log_text.pack(side="left")
log_scrollbar.pack(side="right", fill="y")

# ───────── 히스토리 출력 영역 ─────────
history_label = tk.Label(root, text="📋 탐지/무해화 내역 히스토리")
history_label.pack()
history_frame = tk.Frame(root)
history_frame.pack(pady=5)

history_text = tk.Text(history_frame, height=8, width=95, bg="#2b2b2b", fg="white", wrap=tk.WORD)
history_scrollbar = tk.Scrollbar(history_frame, orient="vertical", command=history_text.yview)
history_text.configure(yscrollcommand=history_scrollbar.set)
history_text.pack(side="left")
history_scrollbar.pack(side="right", fill="y")

# 시작 메시지
root.after(500, lambda: log_append("문서형 악성코드 무해화 시스템 v2.2 시작"))
root.after(1000, update_model_status)

root.mainloop()