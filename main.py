#main.py

import tkinter as tk
from tkinter import filedialog
import os

from PyPDF2 import PdfReader
from PyPDF2.generic import IndirectObject
from utils.office_macro import remove_macro, is_macro_present
from utils.pdf_sanitizer import sanitize_pdf, find_javascript_keys
from utils.hwp_sanitizer import sanitize_hwp

uploaded_files = []
target_files = []

def scan_for_threats():
    log_text.delete(1.0, tk.END)
    history_text.delete(1.0, tk.END)
    for file_path in target_files:
        ext = os.path.splitext(file_path)[1].lower()
        try:
            log_text.insert(tk.END, f"[INFO] 문서 분석: {file_path}\n")
            if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
                # 단순 탐지용
                if is_macro_present(file_path):
                    log_text.insert(tk.END, "[⚠️] 매크로 탐지됨 (vbaProject.bin 존재)\n")
                    history_text.insert(tk.END, f"{os.path.basename(file_path)}\n  └ 탐지: vbaProject.bin\n")
                else:
                    log_text.insert(tk.END, "[OK] 매크로 없음\n")

            elif ext == ".pdf":
                reader = PdfReader(file_path)
                root = reader.trailer.get("/Root", {})
                if isinstance(root, IndirectObject):
                    root = root.get_object()  # ✅ 반드시 직접 디레퍼런싱해야 탐지 가능

                found_keys = find_javascript_keys(root)
                if found_keys:
                    log_text.insert(tk.END, f"[⚠️] JavaScript 의심 요소 탐지됨\n")
                    history_text.insert(tk.END, f"{os.path.basename(file_path)}\n")
                    for key in found_keys:
                        history_text.insert(tk.END, f"  └ 탐지: {key}\n")
                else:
                    log_text.insert(tk.END, "[OK] JavaScript 없음\n")

            elif ext in (".hwp", ".hwpx", ".hwpml"):
                with open(file_path, "rb") as f:
                    data = f.read()
                found = []
                for pattern in [b'Shell', b'cmd', b'urlmon', b'http', b'javascript']:
                    if pattern in data:
                        found.append(pattern.decode())
                if found:
                    log_text.insert(tk.END, f"[⚠️] 위험 문자열 탐지됨\n")
                    history_text.insert(tk.END, f"{os.path.basename(file_path)}\n")
                    for s in found:
                        history_text.insert(tk.END, f"  └ 탐지: {s}\n")
                else:
                    log_text.insert(tk.END, "[OK] 위험 문자열 없음\n")
            else:
                log_text.insert(tk.END, "[X] 지원되지 않는 파일 형식\n")
        except Exception as e:
            log_text.insert(tk.END, f"[ERROR] 처리 중 오류 발생: {str(e)}\n")

# 파일 업로드
def upload_files():
    files = filedialog.askopenfilenames(
        filetypes=[("지원 문서 형식", "*.docx *.docm *.xlsx *.xlsm *.pptx *.pptm *.pdf *.hwp *.hwpx *.hwpml")]
    )
    for f in files:
        if f not in uploaded_files:
            uploaded_files.append(f)
            left_listbox.insert(tk.END, os.path.basename(f))

# → 버튼
def move_to_target():
    selected = left_listbox.curselection()
    for i in selected[::-1]:
        file = uploaded_files[i]
        if file not in target_files:
            target_files.append(file)
            right_listbox.insert(tk.END, os.path.basename(file))
    for i in selected[::-1]:
        left_listbox.delete(i)
        del uploaded_files[i]

# ← 버튼
def remove_from_target():
    selected = right_listbox.curselection()
    for i in selected[::-1]:
        file = target_files[i]
        uploaded_files.append(file)
        left_listbox.insert(tk.END, os.path.basename(file))
        right_listbox.delete(i)
        del target_files[i]

# 무해화 실행
def start_sanitization():
    log_text.delete(1.0, tk.END)
    history_text.delete(1.0, tk.END)
    for file_path in target_files:
        ext = os.path.splitext(file_path)[1].lower()
        try:
            log_text.insert(tk.END, f"[INFO] 문서 분석: {file_path}\n")
            if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
                clean_file, removed = remove_macro(file_path)
                if removed:
                    log_text.insert(tk.END, f"[✔] 매크로 제거됨: → {clean_file}\n")
                    history_text.insert(tk.END, f"{os.path.basename(file_path)}\n  └ 제거: vbaProject.bin\n")
                else:
                    log_text.insert(tk.END, "[OK] 매크로 없음\n")
            elif ext == ".pdf":
                clean_file, removed_keys = sanitize_pdf(file_path)
                if removed_keys:
                    log_text.insert(tk.END, f"[✔] JavaScript 제거됨: → {clean_file}\n")
                    history_text.insert(tk.END, f"{os.path.basename(file_path)}\n")
                    for key in removed_keys:
                        history_text.insert(tk.END, f"  └ 제거: {key}\n")
                else:
                    log_text.insert(tk.END, "[OK] JavaScript 없음\n")
            elif ext in (".hwp", ".hwpx", ".hwpml"):
                clean_file, removed_strings = sanitize_hwp(file_path)
                if removed_strings:
                    log_text.insert(tk.END, f"[✔] 문자열 제거됨: → {clean_file}\n")
                    history_text.insert(tk.END, f"{os.path.basename(file_path)}\n")
                    for s in removed_strings:
                        history_text.insert(tk.END, f"  └ 제거: {s}\n")
                else:
                    log_text.insert(tk.END, "[OK] 위험 문자열 없음\n")
            else:
                log_text.insert(tk.END, "[X] 지원되지 않는 파일 형식입니다\n")
        except Exception as e:
            log_text.insert(tk.END, f"[ERROR] 처리 중 오류 발생: {str(e)}\n")

# ────────────── GUI 구성 ──────────────
root = tk.Tk()
root.title("문서형 악성코드 무해화 시스템")
root.geometry("1000x700")
root.resizable(False, False)

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
tk.Label(right_frame, text="🛡 무해화 대상 문서").pack()
right_listbox = tk.Listbox(right_frame, width=40, height=15)
right_listbox.pack()

# ───────── 중단 버튼들 ─────────
button_frame = tk.Frame(root)
button_frame.pack(pady=10)
tk.Button(button_frame, text="문서 업로드", width=15, command=upload_files).pack(side=tk.LEFT, padx=10)
tk.Button(button_frame, text="악성코드 탐지", width=15, command=scan_for_threats).pack(side=tk.LEFT, padx=10)
tk.Button(button_frame, text="무해화 및 저장", width=15, command=start_sanitization).pack(side=tk.LEFT, padx=10)

# ───────── 로그 출력 영역 ─────────
log_label = tk.Label(root, text="📄 시스템 로그")
log_label.pack()
log_text = tk.Text(root, height=8, width=95)
log_text.pack(pady=5)

# ───────── 히스토리 출력 영역 ─────────
history_label = tk.Label(root, text="📋 무해화 내역 히스토리")
history_label.pack()
history_text = tk.Text(root, height=8, width=95, bg="#f7f7f7")
history_text.pack(pady=5)

root.mainloop()
