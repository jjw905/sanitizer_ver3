import os
import shutil
import zipfile
import tkinter as tk
from tkinter import filedialog, messagebox
from oletools.olevba import VBA_Parser
from PyPDF2 import PdfReader, PdfWriter

uploaded_files = []
target_files = []

# ────────────── 지원 파일 확장자 ──────────────
SUPPORTED_EXTENSIONS = [
    ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm",
    ".pdf", ".hwp", ".hwpx", ".hwpml"
]

# 매크로 탐지
def is_macro_present(file_path):
    vbaparser = VBA_Parser(file_path)
    return vbaparser.detect_vba_macros()

# 매크로 제거 (Office 계열)
def remove_macro(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    temp_dir = "temp_unzip"
    shutil.rmtree(temp_dir, ignore_errors=True)
    os.makedirs(temp_dir, exist_ok=True)

    with zipfile.ZipFile(file_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)

    removed = False
    for folder in ["word", "xl", "ppt"]:
        vba_path = os.path.join(temp_dir, folder, "vbaProject.bin")
        if os.path.exists(vba_path):
            os.remove(vba_path)
            removed = True

    clean_file = f"{os.path.splitext(file_path)[0]}_clean{ext}"
    with zipfile.ZipFile(clean_file, 'w') as zip_out:
        for root, _, files in os.walk(temp_dir):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, temp_dir)
                zip_out.write(abs_path, rel_path)

    shutil.rmtree(temp_dir)
    return clean_file, removed

# PDF JavaScript 제거
def find_javascript_keys(obj, found=None, path=""):
    if found is None:
        found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_str = k if isinstance(k, str) else k.__repr__()
            full_path = f"{path}/{key_str}" if path else key_str
            full_path = full_path.replace("//", "/")
            if key_str in ["/JavaScript", "/JS", "/OpenAction", "/AA"]:
                found.append(full_path)
            find_javascript_keys(v, found, full_path)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            find_javascript_keys(item, found, f"{path}[{i}]")
    return found

def sanitize_pdf(file_path):
    reader = PdfReader(file_path)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    root = reader.trailer["/Root"]
    found_keys = find_javascript_keys(root)
    if "/OpenAction" in writer._root_object:
        writer._root_object.pop("/OpenAction")
    if "/AA" in writer._root_object:
        writer._root_object.pop("/AA")
    if "/Names" in writer._root_object:
        names = writer._root_object["/Names"]
        if "/JavaScript" in names:
            names.pop("/JavaScript")
    clean_file = f"{os.path.splitext(file_path)[0]}_clean.pdf"
    with open(clean_file, "wb") as f:
        writer.write(f)
    return clean_file, found_keys

# HWP/한글 기반 문자열 제거

def sanitize_hwp(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    clean_file = f"{os.path.splitext(file_path)[0]}_clean{ext}"
    removed_strings = []
    with open(file_path, "rb") as f:
        data = f.read()
    for pattern in [b'Shell', b'cmd', b'urlmon', b'http', b'javascript']:
        if pattern in data:
            data = data.replace(pattern, b'[REMOVED]')
            removed_strings.append(pattern.decode())
    with open(clean_file, "wb") as f:
        f.write(data)
    return clean_file, removed_strings

# 파일 업로드
def upload_files():
    files = filedialog.askopenfilenames(filetypes=[("문서 파일", "*.docx *.docm *.pdf")])
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

# ← 버튼 (선택 제거)
def remove_from_target():
    selected = right_listbox.curselection()
    for i in selected[::-1]:
        file = target_files[i]
        uploaded_files.append(file)
        left_listbox.insert(tk.END, os.path.basename(file))
        right_listbox.delete(i)
        del target_files[i]

# 무해화 실행
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

# 왼쪽 리스트
left_frame = tk.Frame(root)
left_frame.grid(row=0, column=0, padx=10, pady=10)
tk.Label(left_frame, text="📂 업로드된 문서").pack()
left_listbox = tk.Listbox(left_frame, width=40, height=15)
left_listbox.pack()

# 중앙 버튼
center_frame = tk.Frame(root)
center_frame.grid(row=0, column=1, padx=10, pady=10)
tk.Button(center_frame, text="→", width=5, command=move_to_target).pack(pady=10)
tk.Button(center_frame, text="←", width=5, command=remove_from_target).pack(pady=10)

# 오른쪽 리스트
right_frame = tk.Frame(root)
right_frame.grid(row=0, column=2, padx=10, pady=10)
tk.Label(right_frame, text="🛡 무해화 대상 문서").pack()
right_listbox = tk.Listbox(right_frame, width=40, height=15)
right_listbox.pack()

# ✅ 하단 프레임 먼저 정의
bottom_frame = tk.Frame(root)
bottom_frame.grid(row=1, column=0, columnspan=3, pady=10)

# 하단 버튼
tk.Button(bottom_frame, text="문서 업로드", command=upload_files).grid(row=0, column=0, padx=10)
tk.Button(bottom_frame, text="무해화 시작", command=start_sanitization).grid(row=0, column=1, padx=10)

# 로그 출력 (왼쪽 하단)
log_text = tk.Text(bottom_frame, height=6, width=70)
log_text.grid(row=1, column=0, pady=10, padx=(0, 5))

# 히스토리 출력 (오른쪽 하단)
history_frame = tk.Frame(bottom_frame)
history_frame.grid(row=1, column=1, padx=(0, 10), pady=10, sticky="n")

tk.Label(history_frame, text="📋 무해화 내역 히스토리").pack()
history_text = tk.Text(history_frame, height=6, width=45, bg="#f7f7f7")
history_text.pack()

root.mainloop()