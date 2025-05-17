# ✅ 문서형 악성코드 무해화 시스템 (main.py - 실행 진입점)

import tkinter as tk
from tkinter import filedialog
import os
from utils.office_macro import remove_macro
from utils.pdf_sanitizer import sanitize_pdf
from utils.hwp_sanitizer import sanitize_hwp

uploaded_files = []
target_files = []

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
root.geometry("880x520")
root.resizable(False, False)

left_frame = tk.Frame(root)
left_frame.grid(row=0, column=0, padx=10, pady=10)
tk.Label(left_frame, text="📂 업로드된 문서").pack()
left_listbox = tk.Listbox(left_frame, width=40, height=15)
left_listbox.pack()

center_frame = tk.Frame(root)
center_frame.grid(row=0, column=1, padx=10, pady=10)
tk.Button(center_frame, text="→", width=5, command=move_to_target).pack(pady=10)
tk.Button(center_frame, text="←", width=5, command=remove_from_target).pack(pady=10)

right_frame = tk.Frame(root)
right_frame.grid(row=0, column=2, padx=10, pady=10)
tk.Label(right_frame, text="🛡 무해화 대상 문서").pack()
right_listbox = tk.Listbox(right_frame, width=40, height=15)
right_listbox.pack()

bottom_frame = tk.Frame(root)
bottom_frame.grid(row=1, column=0, columnspan=3, pady=10)
tk.Button(bottom_frame, text="문서 업로드", command=upload_files).grid(row=0, column=0, padx=10)
tk.Button(bottom_frame, text="무해화 시작", command=start_sanitization).grid(row=0, column=1, padx=10)

log_text = tk.Text(bottom_frame, height=6, width=70)
log_text.grid(row=1, column=0, pady=10, padx=(0, 5))

history_frame = tk.Frame(bottom_frame)
history_frame.grid(row=1, column=1, padx=(0, 10), pady=10, sticky="n")
tk.Label(history_frame, text="📋 무해화 내역 히스토리").pack()
history_text = tk.Text(history_frame, height=6, width=45, bg="#f7f7f7")
history_text.pack()

root.mainloop()
