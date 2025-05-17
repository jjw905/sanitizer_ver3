import os
import shutil
import zipfile
import tkinter as tk
from tkinter import filedialog, messagebox
from oletools.olevba import VBA_Parser
from PyPDF2 import PdfReader, PdfWriter

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

    # /JavaScript, /OpenAction 제거
    writer._root_object.update({
        k: v for k, v in writer._root_object.items()
        if k not in ('/OpenAction', '/AA', '/JavaScript')
    })

    clean_file = f"{os.path.splitext(file_path)[0]}_clean.pdf"
    with open(clean_file, "wb") as f_out:
        writer.write(f_out)

    return clean_file

# 파일 처리 로직
def process_file():
    file_path = filedialog.askopenfilename(
        filetypes=[("문서 파일", "*.docx *.docm *.pdf")]
    )
    if not file_path:
        return

    ext = os.path.splitext(file_path)[1].lower()

    try:
        if ext in (".docx", ".docm"):
            log.insert(tk.END, f"[INFO] Word 문서 분석 중: {file_path}\n")
            if is_macro_present(file_path):
                clean_file = remove_macro(file_path)
                log.insert(tk.END, f"[✔] 매크로 제거됨: {clean_file}\n")
            else:
                log.insert(tk.END, "[OK] 매크로 없음. 무해화 불필요\n")

        elif ext == ".pdf":
            log.insert(tk.END, f"[INFO] PDF 문서 분석 중: {file_path}\n")
            clean_file = sanitize_pdf(file_path)
            log.insert(tk.END, f"[✔] PDF JavaScript 제거됨: {clean_file}\n")

        else:
            log.insert(tk.END, "[X] 지원되지 않는 형식입니다.\n")

    except Exception as e:
        messagebox.showerror("에러 발생", str(e))

# GUI 구성
root = tk.Tk()
root.title("문서형 악성코드 무해화 시스템")
root.geometry("600x400")
root.resizable(False, False)

frame = tk.Frame(root, pady=20)
frame.pack()

btn = tk.Button(frame, text="문서 선택 및 무해화 시작", command=process_file, font=("Arial", 12))
btn.pack(pady=10)

log = tk.Text(root, height=15, width=70)
log.pack(pady=10)

root.mainloop()
