import os
import shutil
import zipfile
import tkinter as tk
from tkinter import filedialog, messagebox
from oletools.olevba import VBA_Parser
from PyPDF2 import PdfReader, PdfWriter

uploaded_files = []
target_files = []

# 매크로 탐지
def is_macro_present(file_path):
    vbaparser = VBA_Parser(file_path)
    return vbaparser.detect_vba_macros()

# 매크로 제거
def remove_macro(file_path):
    temp_dir = "temp_unzip"
    shutil.rmtree(temp_dir, ignore_errors=True)
    os.makedirs(temp_dir, exist_ok=True)

    with zipfile.ZipFile(file_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)

    vba_path = os.path.join(temp_dir, "word", "vbaProject.bin")
    if os.path.exists(vba_path):
        os.remove(vba_path)

    clean_file = f"{os.path.splitext(file_path)[0]}_clean.docx"
    with zipfile.ZipFile(clean_file, 'w') as zip_out:
        for root, _, files in os.walk(temp_dir):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, temp_dir)
                zip_out.write(abs_path, rel_path)

    shutil.rmtree(temp_dir)
    return clean_file

# PDF JavaScript 제거
def sanitize_pdf(file_path):
    reader = PdfReader(file_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    writer._root_object.update({
        k: v for k, v in writer._root_object.items()
        if k not in ('/OpenAction', '/AA', '/JavaScript')
    })

    clean_file = f"{os.path.splitext(file_path)[0]}_clean.pdf"
    with open(clean_file, "wb") as f_out:
        writer.write(f_out)

    return clean_file

# 파일 업로드
def upload_files():
    files = filedialog.askopenfilenames(
        filetypes=[("문서 파일", "*.docx *.docm *.pdf")]
    )
    for f in files:
        if f not in uploaded_files:
            uploaded_files.append(f)
            left_listbox.insert(tk.END, os.path.basename(f))

# → 버튼 동작
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

# 무해화 시작
def start_sanitization():
    log_text.delete(1.0, tk.END)

    for file_path in target_files:
        ext = os.path.splitext(file_path)[1].lower()
        try:
            if ext in (".docx", ".docm"):
                log_text.insert(tk.END, f"[INFO] Word 분석: {file_path}\n")
                if is_macro_present(file_path):
                    clean_file = remove_macro(file_path)
                    log_text.insert(tk.END, f"[✔] 매크로 제거됨: {clean_file}\n")
                else:
                    log_text.insert(tk.END, "[OK] 매크로 없음\n")
            elif ext == ".pdf":
                log_text.insert(tk.END, f"[INFO] PDF 분석: {file_path}\n")
                clean_file = sanitize_pdf(file_path)
                log_text.insert(tk.END, f"[✔] JavaScript 제거됨: {clean_file}\n")
            else:
                log_text.insert(tk.END, "[X] 지원되지 않는 형식\n")
        except Exception as e:
            log_text.insert(tk.END, f"[ERROR] {str(e)}\n")

# ────────────── GUI 구성 ──────────────
root = tk.Tk()
root.title("문서형 악성코드 무해화 시스템")
root.geometry("800x500")
root.resizable(False, False)

# 좌측: 업로드된 파일 목록
left_frame = tk.Frame(root)
left_frame.grid(row=0, column=0, padx=10, pady=10)
tk.Label(left_frame, text="📂 업로드된 문서").pack()
left_listbox = tk.Listbox(left_frame, width=40, height=15)
left_listbox.pack()

# 중앙: 이동 버튼
center_frame = tk.Frame(root)
center_frame.grid(row=0, column=1, padx=10, pady=10)
tk.Button(center_frame, text="→", width=5, command=move_to_target).pack(pady=60)

# 우측: 무해화 대상
right_frame = tk.Frame(root)
right_frame.grid(row=0, column=2, padx=10, pady=10)
tk.Label(right_frame, text="🛡 무해화 대상 문서").pack()
right_listbox = tk.Listbox(right_frame, width=40, height=15)
right_listbox.pack()

# 하단: 버튼 + 로그 출력
bottom_frame = tk.Frame(root)
bottom_frame.grid(row=1, column=0, columnspan=3, pady=10)

tk.Button(bottom_frame, text="문서 업로드", command=upload_files).grid(row=0, column=0, padx=10)
tk.Button(bottom_frame, text="무해화 시작", command=start_sanitization).grid(row=0, column=1, padx=10)

log_text = tk.Text(bottom_frame, height=10, width=95)
log_text.grid(row=1, column=0, columnspan=2, pady=10)

root.mainloop()
