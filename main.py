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

uploaded_files = []
target_files = []
model_manager = get_model_manager()
malware_classifier = MalwareClassifier()


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
    """로그 수동 초기화 (버튼으로만 실행)"""
    log_text.delete(1.0, tk.END)
    history_text.delete(1.0, tk.END)
    log_append("로그가 초기화되었습니다.")


def update_model_status():
    """모델 상태 업데이트"""
    if model_manager.is_model_available():
        if model_manager.load_model():
            model_status_label.config(text="🤖 AI 모델: 활성화됨", fg="green")
            ai_scan_button.config(state="normal")
        else:
            model_status_label.config(text="🤖 AI 모델: 로드 실패", fg="red")
            ai_scan_button.config(state="disabled")
    else:
        model_status_label.config(text="🤖 AI 모델: 비활성화됨 (훈련 필요)", fg="orange")
        ai_scan_button.config(state="disabled")


def classify_malware_type(file_path):
    """악성코드 유형 분류"""
    try:
        malware_type = malware_classifier.classify_malware(file_path)
        return malware_type
    except Exception as e:
        return f"분류 오류: {str(e)}"


def ai_scan_threats():
    """AI 모델을 이용한 악성코드 탐지"""
    if not target_files:
        messagebox.showwarning("경고", "먼저 스캔할 파일을 선택하세요.")
        return

    progress_window = tk.Toplevel(root)
    progress_window.title("AI 스캔 진행 중...")
    progress_window.geometry("400x100")
    progress_window.resizable(False, False)

    progress_label = tk.Label(progress_window, text="AI 모델로 파일을 분석하고 있습니다...")
    progress_label.pack(pady=10)

    progress_bar = ttk.Progressbar(progress_window, mode='indeterminate')
    progress_bar.pack(pady=10, padx=20, fill='x')
    progress_bar.start()

    def scan_thread():
        try:
            log_append("=== AI 기반 악성코드 탐지 시작 ===")

            for i, file_path in enumerate(target_files):
                file_name = os.path.basename(file_path)
                log_append(f"[{i + 1}/{len(target_files)}] 분석 중: {file_name}")

                result = model_manager.predict_file(file_path)

                if "error" in result:
                    log_append(f"[ERROR] {result['error']}")
                    continue

                prediction = result['prediction']
                confidence = result['confidence']
                malware_prob = result.get('malware_probability', 0)

                if prediction == "악성":
                    log_append(f"[⚠️ 위험] AI 예측: {prediction} (신뢰도: {confidence:.3f})")
                    log_append(f"    악성 확률: {malware_prob:.3f}")

                    # 악성코드 유형 분류
                    malware_type = classify_malware_type(file_path)
                    log_append(f"    악성코드 유형: {malware_type}")

                    history_append(f"🚨 {file_name}")
                    history_append(f"  └ AI 예측: {prediction} ({confidence:.3f})")
                    history_append(f"  └ 악성코드 유형: {malware_type}")

                    features = result.get('features', {})
                    if features:
                        suspicious_features = []
                        if features.get('has_macro'):
                            suspicious_features.append("매크로 포함")
                        if features.get('pdf_js_count', 0) > 0:
                            suspicious_features.append(f"JavaScript {features['pdf_js_count']}개")
                        if features.get('suspicious_keywords_count', 0) > 0:
                            suspicious_features.append(f"의심 키워드 {features['suspicious_keywords_count']}개")

                        if suspicious_features:
                            history_append(f"  └ 탐지 요소: {', '.join(suspicious_features)}")

                else:
                    log_append(f"[✅ 안전] AI 예측: {prediction} (신뢰도: {confidence:.3f})")

                ext = os.path.splitext(file_path)[1].lower()
                rule_based_threats = []

                try:
                    if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
                        if is_macro_present(file_path):
                            rule_based_threats.append("매크로 탐지")

                    elif ext == ".pdf":
                        reader = PdfReader(file_path)
                        root_obj = reader.trailer.get("/Root", {})
                        if isinstance(root_obj, IndirectObject):
                            root_obj = root_obj.get_object()

                        found_keys = find_javascript_keys(root_obj)
                        if found_keys:
                            rule_based_threats.extend(found_keys)

                    elif ext in (".hwp", ".hwpx", ".hwpml"):
                        with open(file_path, "rb") as f:
                            data = f.read()
                        for pattern in [b'Shell', b'cmd', b'urlmon', b'http', b'javascript']:
                            if pattern in data:
                                rule_based_threats.append(pattern.decode())

                except Exception as e:
                    log_append(f"[WARNING] 룰 기반 검사 오류: {str(e)}")

                if rule_based_threats:
                    log_append(f"[📋 룰 기반] 탐지 요소: {', '.join(rule_based_threats)}")
                    if prediction == "정상":
                        history_append(f"⚠️ {file_name} (AI는 정상으로 판단)")
                        history_append(f"  └ 룰 기반 탐지: {', '.join(rule_based_threats)}")

                log_append("-" * 50)

            log_append("=== AI 스캔 완료 ===")

        except Exception as e:
            log_append(f"[ERROR] AI 스캔 중 오류: {str(e)}")
        finally:
            progress_bar.stop()
            progress_window.destroy()

    thread = threading.Thread(target=scan_thread)
    thread.daemon = True
    thread.start()


def scan_for_threats():
    """기존 룰 기반 탐지"""
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
root.title("문서형 악성코드 무해화 시스템 v2.1 (개선버전)")
root.geometry("1200x850")
root.resizable(False, False)

# ───────── 상단 모델 상태 ─────────
status_frame = tk.Frame(root)
status_frame.pack(pady=5)

model_status_label = tk.Label(status_frame, text="🤖 AI 모델: 확인 중...", font=("Arial", 10))
model_status_label.pack(side=tk.LEFT, padx=10)

tk.Button(status_frame, text="모델 정보", command=show_model_info).pack(side=tk.LEFT, padx=5)
tk.Button(status_frame, text="모델 재훈련", command=train_model).pack(side=tk.LEFT, padx=5)
tk.Button(status_frame, text="로그 초기화", command=clear_logs, bg="#FF6B6B", fg="white").pack(side=tk.LEFT, padx=5)

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
tk.Button(button_frame, text="룰 기반 탐지", width=15, command=scan_for_threats).pack(side=tk.LEFT, padx=5)

ai_scan_button = tk.Button(button_frame, text="🤖 AI 스캔", width=15, command=ai_scan_threats,
                           bg="#4CAF50", fg="black", font=("Arial", 9, "bold"))
ai_scan_button.pack(side=tk.LEFT, padx=5)

tk.Button(button_frame, text="무해화 및 저장", width=15, command=start_sanitization).pack(side=tk.LEFT, padx=5)

# ───────── 로그 출력 영역 ─────────
log_label = tk.Label(root, text="📄 시스템 로그 (누적)")
log_label.pack()
log_frame = tk.Frame(root)
log_frame.pack(pady=5)

log_text = tk.Text(log_frame, height=8, width=95)
log_scrollbar = tk.Scrollbar(log_frame, orient="vertical", command=log_text.yview)
log_text.configure(yscrollcommand=log_scrollbar.set)
log_text.pack(side="left")
log_scrollbar.pack(side="right", fill="y")

# ───────── 히스토리 출력 영역 ─────────
history_label = tk.Label(root, text="📋 탐지/무해화 내역 히스토리 (누적)")
history_label.pack()
history_frame = tk.Frame(root)
history_frame.pack(pady=5)

history_text = tk.Text(history_frame, height=8, width=95, bg="#f7f7f7")
history_scrollbar = tk.Scrollbar(history_frame, orient="vertical", command=history_text.yview)
history_text.configure(yscrollcommand=history_scrollbar.set)
history_text.pack(side="left")
history_scrollbar.pack(side="right", fill="y")

# 시작 메시지
root.after(500, lambda: log_append("문서형 악성코드 무해화 시스템 v2.1 시작"))
root.after(1000, update_model_status)

root.mainloop()