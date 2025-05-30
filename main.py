# main.py - 개선된 버전

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import threading
from datetime import datetime

from PyPDF2 import PdfReader
from PyPDF2.generic import IndirectObject
from utils.office_macro import remove_macro, is_macro_present
from utils.pdf_sanitizer import sanitize_pdf, find_javascript_keys
from utils.hwp_sanitizer import sanitize_hwp
from utils.model_manager import get_model_manager

uploaded_files = []
target_files = []
model_manager = get_model_manager()

# 전역 히스토리 저장소
detection_history = []
sanitization_history = []


class HistoryManager:
    """히스토리 관리 클래스"""

    @staticmethod
    def add_detection_record(filename, detection_type, details, threat_level="알 수 없음"):
        """탐지 기록 추가"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        record = {
            'timestamp': timestamp,
            'filename': filename,
            'type': detection_type,
            'details': details,
            'threat_level': threat_level
        }
        detection_history.append(record)
        update_history_display()

    @staticmethod
    def add_sanitization_record(filename, removed_items, success=True):
        """무해화 기록 추가"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        record = {
            'timestamp': timestamp,
            'filename': filename,
            'removed_items': removed_items,
            'success': success
        }
        sanitization_history.append(record)
        update_history_display()


def update_history_display():
    """히스토리 화면 업데이트"""
    history_text.config(state='normal')
    history_text.delete(1.0, tk.END)

    # 탐지 기록 표시
    if detection_history:
        history_text.insert(tk.END, "🔍 탐지 기록:\n", "header")
        for record in detection_history[-10:]:  # 최근 10개만 표시
            timestamp = record['timestamp']
            filename = record['filename']
            detection_type = record['type']
            threat_level = record['threat_level']

            if detection_type == "AI":
                icon = "🤖"
                color = "ai_detection"
            elif detection_type == "룰 기반":
                icon = "📋"
                color = "rule_detection"
            else:
                icon = "⚠️"
                color = "general_detection"

            history_text.insert(tk.END, f"{icon} [{timestamp}] {filename}\n", color)
            history_text.insert(tk.END, f"   └ {detection_type} 탐지 | 위험도: {threat_level}\n", "details")
            history_text.insert(tk.END, f"   └ {record['details']}\n\n", "details")

    # 무해화 기록 표시
    if sanitization_history:
        history_text.insert(tk.END, "🛡️ 무해화 기록:\n", "header")
        for record in sanitization_history[-10:]:  # 최근 10개만 표시
            timestamp = record['timestamp']
            filename = record['filename']
            removed_items = record['removed_items']
            success = record['success']

            status_icon = "✅" if success else "❌"
            status_color = "success" if success else "error"

            history_text.insert(tk.END, f"{status_icon} [{timestamp}] {filename}\n", status_color)

            if removed_items:
                history_text.insert(tk.END, f"   └ 제거된 요소: {', '.join(removed_items)}\n\n", "details")
            else:
                history_text.insert(tk.END, f"   └ 위험 요소 없음\n\n", "details")

    history_text.config(state='disabled')
    history_text.see(tk.END)


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


def ai_scan_threats():
    """AI 모델을 이용한 악성코드 탐지"""
    if not target_files:
        messagebox.showwarning("경고", "먼저 스캔할 파일을 선택하세요.")
        return

    log_text.delete(1.0, tk.END)

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
            log_text.insert(tk.END, "=== AI 기반 악성코드 탐지 시작 ===\n")

            for i, file_path in enumerate(target_files):
                file_name = os.path.basename(file_path)
                log_text.insert(tk.END, f"\n[{i + 1}/{len(target_files)}] 분석 중: {file_name}\n")
                root.update()

                result = model_manager.predict_file(file_path)

                if "error" in result:
                    log_text.insert(tk.END, f"[ERROR] {result['error']}\n")
                    continue

                prediction = result['prediction']
                confidence = result['confidence']
                malware_prob = result.get('malware_probability', 0)

                # 악성코드 유형 분석 (features에서 추출)
                features = result.get('features', {})
                threat_type = analyze_threat_type(features, file_path)

                if prediction == "악성":
                    threat_level = get_threat_level(confidence, malware_prob)
                    log_text.insert(tk.END, f"[⚠️ 위험] AI 예측: {prediction} (신뢰도: {confidence:.3f})\n")
                    log_text.insert(tk.END, f"    악성 확률: {malware_prob:.3f}\n")
                    log_text.insert(tk.END, f"    위험도: {threat_level}\n")
                    log_text.insert(tk.END, f"    유형: {threat_type}\n")

                    # 히스토리에 기록
                    details = f"신뢰도: {confidence:.3f}, 유형: {threat_type}"
                    HistoryManager.add_detection_record(file_name, "AI", details, threat_level)

                    suspicious_features = []
                    if features.get('has_macro'):
                        suspicious_features.append("매크로 포함")
                    if features.get('pdf_js_count', 0) > 0:
                        suspicious_features.append(f"JavaScript {features['pdf_js_count']}개")
                    if features.get('suspicious_keywords_count', 0) > 0:
                        suspicious_features.append(f"의심 키워드 {features['suspicious_keywords_count']}개")

                    if suspicious_features:
                        log_text.insert(tk.END, f"    탐지 요소: {', '.join(suspicious_features)}\n")

                else:
                    log_text.insert(tk.END, f"[✅ 안전] AI 예측: {prediction} (신뢰도: {confidence:.3f})\n")

                # 룰 기반 탐지도 함께 실행
                rule_based_threats = perform_rule_based_check(file_path)
                if rule_based_threats:
                    log_text.insert(tk.END, f"[📋 룰 기반] 탐지 요소: {', '.join(rule_based_threats)}\n")

                    # 룰 기반 탐지 기록
                    if prediction == "정상":
                        details = f"룰 기반 탐지: {', '.join(rule_based_threats)}"
                        HistoryManager.add_detection_record(file_name, "룰 기반", details, "중간")

                log_text.insert(tk.END, "-" * 50 + "\n")
                log_text.see(tk.END)
                root.update()

            log_text.insert(tk.END, "\n=== AI 스캔 완료 ===\n")

        except Exception as e:
            log_text.insert(tk.END, f"\n[ERROR] AI 스캔 중 오류: {str(e)}\n")
        finally:
            progress_bar.stop()
            progress_window.destroy()

    thread = threading.Thread(target=scan_thread)
    thread.daemon = True
    thread.start()


def analyze_threat_type(features, file_path):
    """악성코드 유형 분석"""
    file_ext = os.path.splitext(file_path)[1].lower()

    # 파일 확장자 기반 기본 분류
    if file_ext == '.pdf':
        if features.get('pdf_js_count', 0) > 0:
            return "PDF JavaScript 악성코드"
        elif features.get('pdf_openaction', False):
            return "PDF 자동실행 악성코드"
        else:
            return "PDF 기반 위협"

    elif file_ext in ['.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm']:
        if features.get('has_macro', False):
            macro_count = features.get('macro_suspicious_count', 0)
            if macro_count > 5:
                return "고위험 매크로 악성코드"
            elif macro_count > 0:
                return "매크로 기반 악성코드"
            else:
                return "매크로 포함 문서"
        else:
            return "Office 문서 기반 위협"

    elif file_ext in ['.hwp', '.hwpx', '.hwpml']:
        if features.get('hwp_scripts', 0) > 0:
            return "HWP 스크립트 악성코드"
        else:
            return "HWP 기반 위협"

    # 의심 키워드 기반 분류
    suspicious_count = features.get('suspicious_keywords_count', 0)
    if suspicious_count > 10:
        return "다중 위협 악성코드"
    elif suspicious_count > 5:
        return "스크립트 기반 악성코드"
    elif suspicious_count > 0:
        return "의심 활동 탐지"

    return "알 수 없는 위협"


def get_threat_level(confidence, malware_prob):
    """위험도 레벨 결정"""
    if confidence > 0.9 and malware_prob > 0.8:
        return "매우 높음"
    elif confidence > 0.8 and malware_prob > 0.6:
        return "높음"
    elif confidence > 0.7 and malware_prob > 0.4:
        return "중간"
    elif confidence > 0.6:
        return "낮음"
    else:
        return "매우 낮음"


def perform_rule_based_check(file_path):
    """룰 기반 검사 실행"""
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

    except Exception:
        pass

    return rule_based_threats


def scan_for_threats():
    """기존 룰 기반 탐지"""
    log_text.delete(1.0, tk.END)
    log_text.insert(tk.END, "=== 룰 기반 악성코드 탐지 시작 ===\n")

    for file_path in target_files:
        ext = os.path.splitext(file_path)[1].lower()
        file_name = os.path.basename(file_path)

        try:
            log_text.insert(tk.END, f"\n[INFO] 문서 분석: {file_name}\n")

            threats = perform_rule_based_check(file_path)

            if threats:
                log_text.insert(tk.END, f"[⚠️] 위험 요소 탐지됨\n")
                details = f"탐지 요소: {', '.join(threats)}"
                HistoryManager.add_detection_record(file_name, "룰 기반", details, "중간")

                for threat in threats:
                    log_text.insert(tk.END, f"  └ 탐지: {threat}\n")
            else:
                log_text.insert(tk.END, "[OK] 위험 요소 없음\n")

        except Exception as e:
            log_text.insert(tk.END, f"[ERROR] 처리 중 오류 발생: {str(e)}\n")

    log_text.insert(tk.END, "\n=== 룰 기반 스캔 완료 ===\n")


def upload_files():
    """파일 업로드"""
    files = filedialog.askopenfilenames(
        filetypes=[("지원 문서 형식", "*.docx *.docm *.xlsx *.xlsm *.pptx *.pptm *.pdf *.hwp *.hwpx *.hwpml")]
    )
    for f in files:
        if f not in uploaded_files:
            uploaded_files.append(f)
            left_listbox.insert(tk.END, os.path.basename(f))


def move_to_target():
    """→ 버튼"""
    selected = left_listbox.curselection()
    for i in selected[::-1]:
        file = uploaded_files[i]
        if file not in target_files:
            target_files.append(file)
            right_listbox.insert(tk.END, os.path.basename(file))
    for i in selected[::-1]:
        left_listbox.delete(i)
        del uploaded_files[i]


def remove_from_target():
    """← 버튼"""
    selected = right_listbox.curselection()
    for i in selected[::-1]:
        file = target_files[i]
        uploaded_files.append(file)
        left_listbox.insert(tk.END, os.path.basename(file))
        right_listbox.delete(i)
        del target_files[i]


def start_sanitization():
    """무해화 실행"""
    if not target_files:
        messagebox.showwarning("경고", "먼저 무해화할 파일을 선택하세요.")
        return

    log_text.delete(1.0, tk.END)
    log_text.insert(tk.END, "=== 문서 무해화 시작 ===\n")

    for file_path in target_files:
        ext = os.path.splitext(file_path)[1].lower()
        file_name = os.path.basename(file_path)

        try:
            log_text.insert(tk.END, f"\n[INFO] 문서 처리: {file_name}\n")
            removed_items = []

            if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
                clean_file, removed = remove_macro(file_path)
                if removed:
                    removed_items.append("vbaProject.bin")
                    log_text.insert(tk.END, f"[✔] 매크로 제거됨: → {os.path.basename(clean_file)}\n")
                else:
                    log_text.insert(tk.END, "[OK] 매크로 없음\n")

            elif ext == ".pdf":
                clean_file, removed_keys = sanitize_pdf(file_path)
                if removed_keys:
                    removed_items.extend(removed_keys)
                    log_text.insert(tk.END, f"[✔] JavaScript 제거됨: → {os.path.basename(clean_file)}\n")
                else:
                    log_text.insert(tk.END, "[OK] JavaScript 없음\n")

            elif ext in (".hwp", ".hwpx", ".hwpml"):
                clean_file, removed_strings = sanitize_hwp(file_path)
                if removed_strings:
                    removed_items.extend(removed_strings)
                    log_text.insert(tk.END, f"[✔] 문자열 제거됨: → {os.path.basename(clean_file)}\n")
                else:
                    log_text.insert(tk.END, "[OK] 위험 문자열 없음\n")
            else:
                log_text.insert(tk.END, "[X] 지원되지 않는 파일 형식입니다\n")
                continue

            # 무해화 기록 추가
            HistoryManager.add_sanitization_record(file_name, removed_items, True)

        except Exception as e:
            log_text.insert(tk.END, f"[ERROR] 처리 중 오류 발생: {str(e)}\n")
            HistoryManager.add_sanitization_record(file_name, [], False)

    log_text.insert(tk.END, "\n=== 무해화 완료 ===\n")
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
            success = model_manager.train_new_model()
            progress_bar.stop()
            progress_window.destroy()

            if success:
                messagebox.showinfo("성공", "AI 모델 훈련이 완료되었습니다!")
                update_model_status()
            else:
                messagebox.showerror("실패", "AI 모델 훈련에 실패했습니다.")
        except Exception as e:
            progress_bar.stop()
            progress_window.destroy()
            messagebox.showerror("오류", f"훈련 중 오류가 발생했습니다: {str(e)}")

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


def clear_history():
    """히스토리 초기화"""
    global detection_history, sanitization_history
    result = messagebox.askyesno("히스토리 초기화", "모든 히스토리를 삭제하시겠습니까?")
    if result:
        detection_history.clear()
        sanitization_history.clear()
        update_history_display()


# GUI 구성
root = tk.Tk()
root.title("문서형 악성코드 무해화 시스템 v2.0 (AI 통합)")
root.geometry("1200x800")
root.resizable(False, False)

# 상단 모델 상태
status_frame = tk.Frame(root)
status_frame.pack(pady=5)

model_status_label = tk.Label(status_frame, text="🤖 AI 모델: 확인 중...", font=("Arial", 10))
model_status_label.pack(side=tk.LEFT, padx=10)

tk.Button(status_frame, text="모델 정보", command=show_model_info).pack(side=tk.LEFT, padx=5)
tk.Button(status_frame, text="모델 재훈련", command=train_model).pack(side=tk.LEFT, padx=5)

# 상단 문서 리스트
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

# 중단 버튼들
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

tk.Button(button_frame, text="문서 업로드", width=15, command=upload_files).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="룰 기반 탐지", width=15, command=scan_for_threats).pack(side=tk.LEFT, padx=5)

ai_scan_button = tk.Button(button_frame, text="🤖 AI 스캔", width=15, command=ai_scan_threats,
                           bg="#4CAF50", fg="black", font=("Arial", 9, "bold"))
ai_scan_button.pack(side=tk.LEFT, padx=5)

tk.Button(button_frame, text="무해화 및 저장", width=15, command=start_sanitization).pack(side=tk.LEFT, padx=5)

# 로그 출력 영역
log_label = tk.Label(root, text="📄 시스템 로그")
log_label.pack()
log_frame = tk.Frame(root)
log_frame.pack(pady=5)

log_text = tk.Text(log_frame, height=8, width=95)
log_scrollbar = tk.Scrollbar(log_frame, orient="vertical", command=log_text.yview)
log_text.configure(yscrollcommand=log_scrollbar.set)
log_text.pack(side="left")
log_scrollbar.pack(side="right", fill="y")

# 히스토리 출력 영역 (개선된 버전)
history_label_frame = tk.Frame(root)
history_label_frame.pack()
tk.Label(history_label_frame, text="📋 탐지/무해화 내역 히스토리").pack(side=tk.LEFT)
tk.Button(history_label_frame, text="히스토리 초기화", command=clear_history,
          font=("Arial", 8)).pack(side=tk.RIGHT, padx=10)

history_frame = tk.Frame(root)
history_frame.pack(pady=5)

history_text = tk.Text(history_frame, height=8, width=95, bg="#1e1e1e", fg="#ffffff",
                       insertbackground="#ffffff", selectbackground="#404040")
history_scrollbar = tk.Scrollbar(history_frame, orient="vertical", command=history_text.yview)
history_text.configure(yscrollcommand=history_scrollbar.set)
history_text.pack(side="left")
history_scrollbar.pack(side="right", fill="y")

# 히스토리 텍스트 태그 설정
history_text.tag_config("header", foreground="#00ff00", font=("Arial", 10, "bold"))
history_text.tag_config("ai_detection", foreground="#ff6b6b")
history_text.tag_config("rule_detection", foreground="#ffa500")
history_text.tag_config("general_detection", foreground="#ffff00")
history_text.tag_config("success", foreground="#00ff00")
history_text.tag_config("error", foreground="#ff0000")
history_text.tag_config("details", foreground="#cccccc", font=("Arial", 9))

history_text.config(state='disabled')

# 초기 모델 상태 확인
root.after(1000, update_model_status)

root.mainloop()