import os
import shutil
import zipfile

def remove_macro(file_path: str, output_dir: str = "sample/clear") -> tuple[str, bool]:
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
        raise ValueError("지원하지 않는 확장자입니다.")

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

    os.makedirs(output_dir, exist_ok=True)
    file_name = os.path.splitext(os.path.basename(file_path))[0]
    clean_file = os.path.join(output_dir, f"{file_name}_clean{ext}")

    with zipfile.ZipFile(clean_file, 'w') as zip_out:
        for root, _, files in os.walk(temp_dir):
            for file in files:
                abs_path = os.path.join(root, file)
                rel_path = os.path.relpath(abs_path, temp_dir)
                zip_out.write(abs_path, rel_path)

    shutil.rmtree(temp_dir)
    return clean_file, removed
