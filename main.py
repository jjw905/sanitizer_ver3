# main.py - 기존 구조 유지, 색상만 다크모드로 변경

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import threading

from PyPDF2 import PdfReader
from PyPDF2.generic import IndirectObject
from utils.office_macro import remove_macro, is_macro_present
from utils.pdf_sanitizer import sanitize_pdf, find_javascript_keys
from utils.hwp_sanitizer import sanitize_hwp
from utils.model_manager import get_model_manager
from utils.api_client import APIClient

uploaded_files = []
target_files = []
model_manager = get_model_manager()
api_client = APIClient()

# 지원 파일 형식 제한
SUPPORTED_EXTENSIONS = {'.hwp', '.hwpx', '.docx', '.docm', '.pdf', '.pptx', '.pptm', '.xlsx', '.xlsm'}

# 다크모드 색상 정의
COLORS = {
    'bg': '#2d2d2d',           # 메인 배경 (회색)
    'panel_bg': '#1a1a1a',     # 패널 배경 (검정)
    'text': '#ffffff',          # 메인 텍스트 (흰색)
    'button_bg': '#ffffff',     # 버튼 배경 (흰색)
    'button_text': '#000000',   # 버튼 텍스트 (검정)
    'listbox_bg': '#1a1a1a',    # 리스트박스 배경 (검정)
    'textbox_bg': '#1a1a1a',    # 텍스트박스 배경 (검정)
    'select_bg': '#4CAF50',     # 선택 배경 (녹색)
    'select_bg_red': '#FF5722', # 선택 배경 (빨간색)
}


def is_supported_file(file_path):
    """지원되는 파일 형식인지 확인"""
    ext = os.path.splitext(file_path)[1].lower()
    return ext in SUPPORTED_EXTENSIONS


def virus_scan_with_virustotal(file_path):
    """VirusTotal로 추가 검증"""
    try:
        result = api_client.check_file_with_virustotal(file_path)
        if "error" in result:
            return None, result["error"]

        total_engines = result.get("total", 0)
        malicious_count = result.get("malicious", 0)

        if total_engines > 0:
            malicious_ratio = malicious_count / total_engines
            if malicious_ratio > 0.1:  # 10% 이상의 엔진에서 악성으로 판단
                return True, f"VirusTotal: {malicious_count}/{total_engines} 엔진에서 악성 탐지"
            else:
                return False, f"VirusTotal: 안전함 ({malicious_count}/{total_engines})"
        else:
            return None, "VirusTotal: 분석 결과 없음"

    except Exception as e:
        return None, f"VirusTotal 검사 오류: {str(e)}"


def ai_virus_scan():
    """AI 기반 바이러스 검사"""
    if not target_files:
        messagebox.showwarning("경고", "먼저 검사할 파일을 선택하세요.")
        return

    log_text.delete(1.0, tk.END)
    history_text.delete(1.0, tk.END)

    # 프로그레스 창 (다크모드 색상 적용)
    progress_window = tk.Toplevel(root)
    progress_window.title("바이러스 검사 진행 중...")
    progress_window.geometry("400x100")
    progress_window.resizable(False, False)
    progress_window.configure(bg=COLORS['panel_bg'])

    progress_label = tk.Label(progress_window, text="AI 모델로 파일을 분석하고 있습니다...",
                              bg=COLORS['panel_bg'], fg=COLORS['text'])
    progress_label.pack(pady=10)

    progress_bar = ttk.Progressbar(progress_window, mode='indeterminate')
    progress_bar.pack(pady=10, padx=20, fill='x')
    progress_bar.start()

    def scan_thread():
        try:
            log_text.insert(tk.END, "=== AI 바이러스 검사 시작 ===\n")

            for i, file_path in enumerate(target_files):
                file_name = os.path.basename(file_path)
                log_text.insert(tk.END, f"\n[{i + 1}/{len(target_files)}] 분석 중: {file_name}\n")
                root.update()

                # AI 모델 예측
                result = model_manager.predict_file(file_path)

                if "error" in result:
                    log_text.insert(tk.END, f"[ERROR] {result['error']}\n")
                    continue

                prediction = result['prediction']
                confidence = result['confidence']
                malware_prob = result.get('malware_probability', 0)

                # AI 예측 결과 출력
                if prediction == "악성":
                    log_text.insert(tk.END, f"[⚠️ 위험] AI 예측: {prediction} (신뢰도: {confidence:.3f})\n")
                    history_text.insert(tk.END, f"🚨 {file_name}\n")
                    history_text.insert(tk.END, f"  └ AI 예측: {prediction} ({confidence:.3f})\n")
                else:
                    log_text.insert(tk.END, f"[✅ 안전] AI 예측: {prediction} (신뢰도: {confidence:.3f})\n")

                    # AI가 안전하다고 판단한 경우 VirusTotal로 추가 검증
                    log_text.insert(tk.END, f"[🔍] VirusTotal 추가 검증 중...\n")
                    vt_is_malicious, vt_message = virus_scan_with_virustotal(file_path)

                    if vt_is_malicious is True:
                        log_text.insert(tk.END, f"[⚠️ 경고] {vt_message}\n")
                        history_text.insert(tk.END, f"⚠️ {file_name} (AI는 안전으로 판단했으나 VirusTotal에서 위험 탐지)\n")
                        history_text.insert(tk.END, f"  └ {vt_message}\n")
                    elif vt_is_malicious is False:
                        log_text.insert(tk.END, f"[✅] {vt_message}\n")
                    else:
                        log_text.insert(tk.END, f"[ℹ️] {vt_message}\n")

                # 룰 기반 탐지 추가 정보
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

                    elif ext in (".hwp", ".hwpx"):
                        with open(file_path, "rb") as f:
                            data = f.read()
                        for pattern in [b'Shell', b'cmd', b'urlmon', b'http', b'javascript']:
                            if pattern in data:
                                rule_based_threats.append(pattern.decode())

                except Exception as e:
                    log_text.insert(tk.END, f"[WARNING] 룰 기반 검사 오류: {str(e)}\n")

                if rule_based_threats:
                    log_text.insert(tk.END, f"[📋 추가 탐지] {', '.join(rule_based_threats)}\n")

                log_text.insert(tk.END, "-" * 50 + "\n")
                log_text.see(tk.END)
                root.update()

            log_text.insert(tk.END, "\n=== 바이러스 검사 완료 ===\n")

        except Exception as e:
            log_text.insert(tk.END, f"\n[ERROR] 검사 중 오류: {str(e)}\n")
        finally:
            progress_bar.stop()
            progress_window.destroy()

    thread = threading.Thread(target=scan_thread)
    thread.daemon = True
    thread.start()


def upload_files():
    """파일 업로드 (지원 형식만)"""
    files = filedialog.askopenfilenames(
        filetypes=[
            ("지원 문서 형식", "*.hwp *.hwpx *.docx *.docm *.pdf *.pptx *.pptm *.xlsx *.xlsm"),
            ("한글 문서", "*.hwp *.hwpx"),
            ("PDF 문서", "*.pdf"),
            ("Word 문서", "*.docx *.docm"),
            ("PowerPoint 문서", "*.pptx *.pptm"),
            ("Excel 문서", "*.xlsx *.xlsm")
        ]
    )

    added_count = 0
    for f in files:
        if is_supported_file(f) and f not in uploaded_files:
            uploaded_files.append(f)
            left_listbox.insert(tk.END, os.path.basename(f))
            added_count += 1
        elif not is_supported_file(f):
            messagebox.showwarning("지원되지 않는 파일",
                                   f"파일 '{os.path.basename(f)}'는 지원되지 않는 형식입니다.\n"
                                   f"지원 형식: HWP, PDF, DOCX, PPTX, XLSX")

    if added_count > 0:
        log_text.insert(tk.END, f"[INFO] {added_count}개 파일이 업로드되었습니다.\n")


def move_to_target():
    """타겟 목록으로 이동"""
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
    """타겟 목록에서 제거"""
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
    history_text.delete(1.0, tk.END)

    log_text.insert(tk.END, "=== 문서 무해화 시작 ===\n")

    for file_path in target_files:
        ext = os.path.splitext(file_path)[1].lower()
        file_name = os.path.basename(file_path)

        try:
            log_text.insert(tk.END, f"\n[INFO] 문서 처리: {file_name}\n")

            if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
                clean_file, removed = remove_macro(file_path)
                if removed:
                    log_text.insert(tk.END, f"[✔] 매크로 제거됨: → {os.path.basename(clean_file)}\n")
                    history_text.insert(tk.END, f"{file_name}\n  └ 제거: vbaProject.bin\n")
                else:
                    log_text.insert(tk.END, "[OK] 매크로 없음\n")

            elif ext == ".pdf":
                clean_file, removed_keys = sanitize_pdf(file_path)
                if removed_keys:
                    log_text.insert(tk.END, f"[✔] JavaScript 제거됨: → {os.path.basename(clean_file)}\n")
                    history_text.insert(tk.END, f"{file_name}\n")
                    for key in removed_keys:
                        history_text.insert(tk.END, f"  └ 제거: {key}\n")
                else:
                    log_text.insert(tk.END, "[OK] JavaScript 없음\n")

            elif ext in (".hwp", ".hwpx"):
                clean_file, removed_strings = sanitize_hwp(file_path)
                if removed_strings:
                    log_text.insert(tk.END, f"[✔] 위험 요소 제거됨: → {os.path.basename(clean_file)}\n")
                    history_text.insert(tk.END, f"{file_name}\n")
                    for s in removed_strings:
                        history_text.insert(tk.END, f"  └ 제거: {s}\n")
                else:
                    log_text.insert(tk.END, "[OK] 위험 요소 없음\n")
            else:
                log_text.insert(tk.END, "[X] 지원되지 않는 파일 형식입니다\n")

        except Exception as e:
            log_text.insert(tk.END, f"[ERROR] 처리 중 오류 발생: {str(e)}\n")

    log_text.insert(tk.END, "\n=== 무해화 완료 ===\n")
    messagebox.showinfo("완료", "문서 무해화가 완료되었습니다!\n정리된 파일은 sample/clear 폴더에 저장되었습니다.")


def update_model():
    """모델 업데이트 (증분 학습)"""
    response = messagebox.askyesno("모델 업데이트",
                                   "기존 모델을 업데이트하시겠습니까?\n"
                                   "새로운 데이터로 추가 학습을 진행합니다.")
    if not response:
        return

    # 프로그레스 창 (다크모드 색상)
    progress_window = tk.Toplevel(root)
    progress_window.title("모델 업데이트 중...")
    progress_window.geometry("400x150")
    progress_window.resizable(False, False)
    progress_window.configure(bg=COLORS['panel_bg'])

    progress_label = tk.Label(progress_window, text="AI 모델을 업데이트하고 있습니다...\n잠시만 기다려주세요.",
                              bg=COLORS['panel_bg'], fg=COLORS['text'])
    progress_label.pack(pady=20)

    progress_bar = ttk.Progressbar(progress_window, mode='indeterminate')
    progress_bar.pack(pady=10, padx=20, fill='x')
    progress_bar.start()

    def training_thread():
        try:
            # 증분 학습으로 모델 업데이트
            success = model_manager.train_new_model(incremental=True)
            progress_bar.stop()
            progress_window.destroy()

            if success:
                messagebox.showinfo("성공", "AI 모델 업데이트가 완료되었습니다!")
                # 성능 정보 표시
                performance = model_manager.get_model_performance_summary()
                if "error" not in performance:
                    performance_msg = (f"업데이트된 모델 성능:\n"
                                       f"정확도: {performance['accuracy']}\n"
                                       f"테스트 샘플: {performance['test_samples']}개")
                    log_text.insert(tk.END, f"[INFO] {performance_msg}\n")
            else:
                messagebox.showerror("실패", "AI 모델 업데이트에 실패했습니다.")
        except Exception as e:
            progress_bar.stop()
            progress_window.destroy()
            messagebox.showerror("오류", f"업데이트 중 오류가 발생했습니다: {str(e)}")

    thread = threading.Thread(target=training_thread)
    thread.daemon = True
    thread.start()


def show_model_status():
    """모델 학습 상태 표시"""
    info = model_manager.get_model_info()
    data_status = model_manager.get_training_data_status()
    format_info = model_manager.get_supported_formats_info()

    status_text = f"""=== 모델 학습 상태 ===

모델 상태: {'사용 가능' if info['model_available'] else '없음'}

학습 데이터 (지원 형식만):
  - 악성 샘플: {data_status['malware_samples']}개
  - 정상 샘플: {data_status['clean_samples']}개
  - 총 샘플: {data_status['total_samples']}개
  - 데이터 충분성: {'충분' if data_status['sufficient_data'] else '부족'}

지원 파일 형식: {format_info['total_supported']}개
  - HWP, DOCX, PDF, PPTX, XLSX 등

"""

    if info['model_available']:
        status_text += f"""모델 파일 정보:
  - 모델 크기: {info.get('model_size_mb', 0)} MB
  - 스케일러 크기: {info.get('scaler_size_kb', 0)} KB
  - 훈련 기록: {'있음' if info.get('training_history_available', False) else '없음'}
"""

        # 성능 정보 추가
        performance = model_manager.get_model_performance_summary()
        if "error" not in performance:
            status_text += f"""
모델 성능:
  - 정확도: {performance['accuracy']}
  - 정밀도: {performance['precision']}
  - 재현율: {performance['recall']}
  - F1 점수: {performance['f1_score']}
"""

    messagebox.showinfo("모델 학습 상태", status_text)


# ────────────── GUI 구성 (기존 구조 유지, 색상만 변경) ──────────────
root = tk.Tk()
root.title("문서형 악성코드 무해화 시스템 v2.0")
root.geometry("1200x800")
root.resizable(False, False)
root.configure(bg=COLORS['bg'])

# ───────── 상단 관리 버튼 ─────────
mgmt_frame = tk.Frame(root, bg=COLORS['bg'])
mgmt_frame.pack(pady=5)

tk.Button(mgmt_frame, text="모델 학습 상태", command=show_model_status,
          width=15, bg=COLORS['button_bg'], fg=COLORS['button_text'],
          activebackground="#d0d0d0", relief="flat", bd=0).pack(side=tk.LEFT, padx=5)
tk.Button(mgmt_frame, text="모델 업데이트", command=update_model,
          width=15, bg=COLORS['button_bg'], fg=COLORS['button_text'],
          activebackground="#d0d0d0", relief="flat", bd=0).pack(side=tk.LEFT, padx=5)

# ───────── 파일 리스트 영역 ─────────
top_frame = tk.Frame(root, bg=COLORS['bg'])
top_frame.pack(pady=15)

left_frame = tk.Frame(top_frame, bg=COLORS['bg'])
left_frame.pack(side=tk.LEFT, padx=20)
tk.Label(left_frame, text="📂 업로드된 문서", bg=COLORS['bg'], fg=COLORS['text'], font=("Arial", 10, "bold")).pack()
left_listbox = tk.Listbox(left_frame, width=40, height=15, bg=COLORS['listbox_bg'], fg=COLORS['text'],
                          selectbackground=COLORS['select_bg'], selectforeground="black")
left_listbox.pack()

center_frame = tk.Frame(top_frame, bg=COLORS['bg'])
center_frame.pack(side=tk.LEFT, padx=10)
tk.Button(center_frame, text="→", width=5, command=move_to_target,
          bg=COLORS['button_bg'], fg=COLORS['button_text'], activebackground="#d0d0d0",
          relief="flat", bd=0).pack(pady=10)
tk.Button(center_frame, text="←", width=5, command=remove_from_target,
          bg=COLORS['button_bg'], fg=COLORS['button_text'], activebackground="#d0d0d0",
          relief="flat", bd=0).pack(pady=10)

right_frame = tk.Frame(top_frame, bg=COLORS['bg'])
right_frame.pack(side=tk.LEFT, padx=20)
tk.Label(right_frame, text="🛡 검사/무해화 대상 문서", bg=COLORS['bg'], fg=COLORS['text'], font=("Arial", 10, "bold")).pack()
right_listbox = tk.Listbox(right_frame, width=40, height=15, bg=COLORS['listbox_bg'], fg=COLORS['text'],
                           selectbackground=COLORS['select_bg_red'], selectforeground="white")
right_listbox.pack()

# ───────── 기능 버튼들 ─────────
button_frame = tk.Frame(root, bg=COLORS['bg'])
button_frame.pack(pady=10)

tk.Button(button_frame, text="문서 업로드", width=15, command=upload_files,
          bg="#2196F3", fg="black", activebackground="#1976D2",
          font=("Arial", 9, "bold"), relief="flat", bd=0).pack(side=tk.LEFT, padx=5)

tk.Button(button_frame, text="바이러스 검사", width=15, command=ai_virus_scan,
          bg="#4CAF50", fg="black", activebackground="#388E3C",
          font=("Arial", 9, "bold"), relief="flat", bd=0).pack(side=tk.LEFT, padx=5)

tk.Button(button_frame, text="무해화 및 저장", width=15, command=start_sanitization,
          bg="#FF9800", fg="black", activebackground="#F57C00",
          font=("Arial", 9, "bold"), relief="flat", bd=0).pack(side=tk.LEFT, padx=5)

# ───────── 로그 출력 영역 ─────────
log_label = tk.Label(root, text="📄 시스템 로그", bg=COLORS['bg'], fg=COLORS['text'], font=("Arial", 10, "bold"))
log_label.pack()
log_frame = tk.Frame(root, bg=COLORS['bg'])
log_frame.pack(pady=5)

log_text = tk.Text(log_frame, height=8, width=95, bg=COLORS['textbox_bg'], fg=COLORS['text'],
                   insertbackground=COLORS['text'], selectbackground=COLORS['select_bg'])
log_scrollbar = tk.Scrollbar(log_frame, orient="vertical", command=log_text.yview,
                            bg=COLORS['bg'], troughcolor=COLORS['bg'],
                            activebackground='#555555', highlightbackground=COLORS['bg'])
log_text.configure(yscrollcommand=log_scrollbar.set)
log_text.pack(side="left")
log_scrollbar.pack(side="right", fill="y")

# ───────── 히스토리 출력 영역 ─────────
history_label = tk.Label(root, text="📋 탐지/무해화 내역 히스토리", bg=COLORS['bg'], fg=COLORS['text'], font=("Arial", 10, "bold"))
history_label.pack()
history_frame = tk.Frame(root, bg=COLORS['bg'])
history_frame.pack(pady=5)

history_text = tk.Text(history_frame, height=8, width=95, bg=COLORS['textbox_bg'], fg=COLORS['text'],
                       insertbackground=COLORS['text'], selectbackground=COLORS['select_bg_red'])
history_scrollbar = tk.Scrollbar(history_frame, orient="vertical", command=history_text.yview,
                                bg=COLORS['bg'], troughcolor=COLORS['bg'],
                                activebackground='#555555', highlightbackground=COLORS['bg'])
history_text.configure(yscrollcommand=history_scrollbar.set)
history_text.pack(side="left")
history_scrollbar.pack(side="right", fill="y")

# 시작 메시지
log_text.insert(tk.END, "=== 문서형 악성코드 무해화 시스템 v2.0 ===\n")
log_text.insert(tk.END, "지원 형식: HWP, DOCX, PDF, PPTX, XLSX\n")
log_text.insert(tk.END, "시스템이 준비되었습니다.\n")

root.mainloop()